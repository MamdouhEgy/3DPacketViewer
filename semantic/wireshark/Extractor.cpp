// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include "Extractor.h"
#include <limits>
#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/range.h>
#include <epan/ftypes/ftypes.h>
#include <QSet>
#include <cmath>
#include <algorithm>
namespace sspa
{
static QVariant scalar(field_info* f)
{
    switch (f->hfinfo->type) {
    case FT_BOOLEAN:
        return bool(fvalue_get_uinteger64(f->value));
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    case FT_FRAMENUM:
        return qint64(fvalue_get_uinteger(f->value));
    case FT_UINT40:
    case FT_UINT48:
    case FT_UINT56:
    case FT_UINT64: {
        const auto n = fvalue_get_uinteger64(f->value);
        return n <= 9007199254740991ULL ? QVariant(qint64(n)) : QVariant();
    }
    case FT_INT8:
    case FT_INT16:
    case FT_INT24:
    case FT_INT32:
        return qint64(fvalue_get_sinteger(f->value));
    case FT_INT40:
    case FT_INT48:
    case FT_INT56:
    case FT_INT64:
        return qint64(fvalue_get_sinteger64(f->value));
    case FT_FLOAT:
    case FT_DOUBLE: {
        const double n = fvalue_get_floating(f->value);
        return std::isfinite(n) ? QVariant(n) : QVariant();
    }
    case FT_ABSOLUTE_TIME:
    case FT_RELATIVE_TIME: {
        const auto* n = fvalue_get_time(f->value);
        return n ? QVariant(double(n->secs) * 1000 + n->nsecs / 1e6) : QVariant();
    }
    case FT_STRING:
    case FT_STRINGZ:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
        if (fvalue_length2(f->value) > 256)
            return {};
        [[fallthrough]];
    case FT_IPv4:
    case FT_IPv6:
    case FT_ETHER: {
        char* text = fvalue_to_string_repr(nullptr, f->value, FTREPR_DISPLAY, f->hfinfo->display);
        QString s = text ? QString::fromUtf8(text).left(256) : QString();
        wmem_free(nullptr, text);
        return s;
    }
    case FT_NONE:
    case FT_PROTOCOL:
        return true;
    default:
        return {};
    }
}
QStringList Extractor::missingFields()
{
    QStringList missing;
    for (auto it = semanticFields().begin(); it != semanticFields().end(); ++it)
        if (!proto_registrar_get_byname(it.key().toUtf8().constData()))
            missing << it.key();
    return missing;
}
QString Extractor::tapFilter()
{
    QStringList fields;
    for (auto it = semanticFields().begin(); it != semanticFields().end(); ++it)
        if (proto_registrar_get_byname(it.key().toUtf8().constData()))
            fields << it.key();
    return fields.join(" || ");
}
DecodedPacket Extractor::copy(epan_dissect_t* edt, packet_info* pinfo)
{
    DecodedPacket p;
    if (!edt || !edt->tree || !pinfo)
        return p;
    p.frame = pinfo->num;
    if (!pinfo->fd || !pinfo->fd->has_ts) {
        p.timeMs = std::numeric_limits<double>::quiet_NaN();
        p.diagnostic = "Capture-relative timestamp unavailable; temporal events omitted.";
    } else
        p.timeMs = double(pinfo->rel_ts.secs) * 1000 + pinfo->rel_ts.nsecs / 1e6;
    if (const auto* ports = prefs_get_range_value("mbtcp", "tcp.port")) {
        const bool src = value_is_in_range(ports, pinfo->srcport),
                   dst = value_is_in_range(ports, pinfo->destport);
        p.modbusRequest = !src && dst;
        p.modbusResponse = src && !dst;
    }
    const QSet<QString> roots { "iec60870_104", "iec60870_asdu", "goose", "r-goose", "sv", "mbtcp", "modbus",
        "mms", "dnp3" };
    struct Work {
        proto_node* node;
        QVector<int> ancestors;
        int group;
    };
    QVector<Work> work;
    if (edt->tree->first_child)
        work.push_back({ edt->tree->first_child, {}, -1 });
    QVector<const tvbuff_t*> sources;
    int nodes = 0, copied = 0;
    while (!work.empty()) {
        auto item = work.takeLast();
        const int id = nodes++;
        if (item.node->next)
            work.push_back({ item.node->next, item.ancestors, item.group });
        if (nodes > 100000 || copied >= 8192) {
            p.diagnostic = "Per-frame semantic extraction limit reached; events are partial.";
            break;
        }
        if (item.ancestors.size() > 128) {
            p.diagnostic = "Protocol nesting exceeds semantic depth limit.";
            continue;
        }
        auto* f = item.node->finfo;
        const QString name = f && f->hfinfo ? QString::fromUtf8(f->hfinfo->abbrev) : QString();
        if (roots.contains(name)) {
            item.group = p.groups.size();
            p.groups.push_back({ name, id, {} });
        }
        if (f && f->hfinfo && !(f->flags & FI_HIDDEN) && semanticFields().contains(name)) {
            QVariant value = scalar(f);
            if (value.isValid()) {
                int source = sources.indexOf(f->ds_tvb);
                if (source < 0 && f->ds_tvb) {
                    source = sources.size();
                    sources.push_back(f->ds_tvb);
                }
                Evidence evidence { p.frame, name, id, source, f->start, f->length,
                    bool(f->flags & FI_GENERATED) };
                for (GSList* source = pinfo->data_src; source; source = source->next) {
                    const auto* ds = static_cast<const data_source*>(source->data);
                    if (get_data_source_tvb(ds) == f->ds_tvb) {
                        evidence.sourceName = QString::fromUtf8(get_data_source_name(ds)).left(256);
                        break;
                    }
                }
                evidence.currentFrameSource = edt->tvb && f->ds_tvb == tvb_get_ds_tvb(edt->tvb);
                DecodedField decoded { name, { value, { evidence } },
                    item.ancestors.empty() ? -1 : item.ancestors.back(), item.ancestors };
                if (item.group < 0)
                    p.common.push_back(decoded);
                else
                    p.groups[item.group].fields.push_back(decoded);
                if (name == "_ws.malformed")
                    p.malformed = true;
                ++copied;
            }
        }
        item.ancestors.push_back(id);
        if (item.node->first_child)
            work.push_back({ item.node->first_child, item.ancestors, item.group });
    }
    for (const auto& group : p.groups)
        if (group.protocol == "r-goose"
            && std::none_of(group.fields.begin(), group.fields.end(),
                [](const DecodedField& f) { return f.name == "goose.gocbRef"; }))
            p.diagnostic = "R-GOOSE recognized, but no decoded GOOSE PDU is available from Wireshark; "
                           "publisher analysis is unavailable for this content.";
    return p;
}
}
