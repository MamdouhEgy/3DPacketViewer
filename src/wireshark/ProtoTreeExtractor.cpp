// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include "ProtoTreeExtractor.h"
#include "core/FieldRangeResolver.h"
#include <epan/packet.h>
#include <epan/ftypes/ftypes.h>
#include <QElapsedTimer>
#include <QHash>
#include <QStringList>
namespace pv
{
Packet ProtoTreeExtractor::extract(epan_dissect_t* edt, uint32_t frame, uint64_t captured, uint64_t reported,
    int linkType, uint64_t generation)
{
    QElapsedTimer timer;
    timer.start();
    auto m = std::make_shared<PacketModel>();
    m->frame = frame;
    m->captured = captured;
    m->reported = reported;
    m->linkType = linkType;
    m->generation = generation;
    if (!edt || !edt->tree) {
        m->diagnostic = "No protocol tree available";
        return m;
    }
    QHash<const tvbuff_t*, int> sources;
    uint64_t budget = 64 * 1024 * 1024;
    uint64_t textBudget = 32 * 1024 * 1024;
    for (GSList* s = edt->pi.data_src; s; s = s->next) {
        const auto* ds = static_cast<const data_source*>(s->data);
        auto* tvb = get_data_source_tvb(ds);
        if (!tvb || sources.contains(tvb))
            continue;
        const auto length = tvb_captured_length(tvb);
        if (length > budget) {
            m->diagnostic = "Data-source copy limit (64 MiB) exceeded; source omitted";
            continue;
        }
        DataSource out;
        out.name = QString::fromUtf8(get_data_source_name(ds));
        out.captured = length;
        out.reported = tvb_reported_length(tvb);
        out.currentFrame = edt->tvb && tvb == tvb_get_ds_tvb(edt->tvb);
        out.provenance = out.currentFrame
            ? "Current captured frame"
            : "Additional Wireshark data source (derived/reassembled/transformed; origin not exposed)";
        out.bytes.resize(length);
        if (length)
            tvb_memcpy(tvb, out.bytes.data(), 0, length);
        budget -= length;
        sources.insert(tvb, m->sources.size());
        m->sources.push_back(std::move(out));
    }
    struct Pending {
        proto_node* node;
        int parent, protocol, depth;
    };
    QVector<Pending> pending;
    if (edt->tree->first_child)
        pending.push_back({ edt->tree->first_child, -1, -1, 0 });
    QStringList protocols;
    while (!pending.empty()) {
        const auto p = pending.takeLast();
        auto* node = p.node;
        if (m->fields.size() >= 100000) {
            m->diagnostic = "Protocol tree limit (100000 nodes) reached; remaining nodes omitted";
            break;
        }
        if (node->next)
            pending.push_back({ node->next, p.parent, p.protocol, p.depth });
        const auto* fi = node->finfo;
        if (!fi || !fi->hfinfo) {
            if (node->first_child)
                pending.push_back({ node->first_child, p.parent, p.protocol, p.depth });
            continue;
        }
        const auto* hf = fi->hfinfo;
        Field f;
        f.id = m->fields.size();
        f.parent = p.parent;
        f.depth = p.depth;
        f.hfId = hf->id;
        f.protocolId = hf->parent;
        f.type = hf->type;
        f.abbreviation = QString::fromUtf8(hf->abbrev);
        f.name = QString::fromUtf8(hf->name);
        f.description = QString::fromUtf8(hf->blurb);
        f.typeName = QString::fromLatin1(ftype_name(hf->type));
        char label[ITEM_LABEL_LENGTH];
        if (fi->rep)
            f.display = QString::fromUtf8(fi->rep->representation);
        else {
            proto_item_fill_label(fi, label, nullptr);
            f.display = QString::fromUtf8(label);
        }
        const bool variableLength
            = FT_IS_STRING(hf->type) || hf->type == FT_BYTES || hf->type == FT_UINT_BYTES;
        const bool largeValue = fi->value && variableLength && fvalue_length2(fi->value) > 4096;
        if (fi->value && hf->type != FT_PROTOCOL && hf->type != FT_NONE && !largeValue) {
            char* value = fvalue_to_string_repr(nullptr, fi->value, FTREPR_DFILTER, hf->display);
            if (value) {
                f.rawValue = QString::fromUtf8(value);
                wmem_free(nullptr, value);
            }
        }
        const auto textSize = uint64_t(f.abbreviation.size() + f.name.size() + f.description.size()
                                  + f.display.size() + f.rawValue.size() + f.typeName.size())
            * 2;
        if (textSize > textBudget) {
            m->diagnostic = "Field text copy limit (32 MiB) reached; remaining nodes omitted";
            break;
        }
        textBudget -= textSize;
        if (f.rawValue.isEmpty() && largeValue)
            f.rawValue = "Value exceeds display limit; inspect source bytes";
        f.start = fi->start;
        f.length = fi->length;
        f.appendixStart = fi->appendix_start;
        f.appendixLength = fi->appendix_length;
        f.mask = hf->bitmask;
        f.flags = fi->flags;
        f.bitOffset = FI_GET_BITS_OFFSET(fi);
        f.bitSize = FI_GET_BITS_SIZE(fi);
        f.generated = FI_GET_FLAG(fi, FI_GENERATED);
        f.hidden = FI_GET_FLAG(fi, FI_HIDDEN);
        f.littleEndian = FI_GET_FLAG(fi, FI_LITTLE_ENDIAN);
        f.bigEndian = FI_GET_FLAG(fi, FI_BIG_ENDIAN);
        f.protocolLayer = fi->proto_layer_num;
        f.totalLayer = fi->total_layer_num;
        f.protocolGroup = hf->type == FT_PROTOCOL;
        f.structural = node->first_child != nullptr;
        f.protocolNode = f.protocolGroup ? f.id : p.protocol;
        if (f.protocolGroup) {
            f.protocol = f.abbreviation;
            protocols.push_back(f.protocol);
        } else if (p.protocol >= 0)
            f.protocol = m->fields[p.protocol].abbreviation;
        f.source = sources.value(fi->ds_tvb, -1);
        FieldRangeResolver::resolve(f, m->sources);
        const auto id = f.id, protocol = f.protocolNode;
        m->fields.push_back(std::move(f));
        if (node->first_child)
            pending.push_back({ node->first_child, id, protocol, p.depth + 1 });
    }
    m->protocols = protocols.join(" → ");
    const auto error = validateModel(*m);
    if (!error.isEmpty()) {
        m->fields.clear();
        m->diagnostic = "Invalid dissection model: " + error;
    }
    m->extractionMs = timer.nsecsElapsed() / 1e6;
    return m;
}
}
