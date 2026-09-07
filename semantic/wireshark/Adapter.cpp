// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include "Adapter.h"
#include "Extractor.h"
#include <epan/tap.h>
#include <epan/funnel.h>
#include <epan/cfile.h>
#include <ui/plugins/include/plugin_if.h>
#include <QWidget>
#include <QTreeView>
#include <epan/column.h>
#include <QThread>
namespace sspa
{
Adapter::Adapter(QWidget* host, QObject* parent)
    : QObject(parent)
{
    for (auto* view : host->findChildren<QTreeView*>())
        if (view->inherits("PacketList")) {
            packetList = view;
            break;
        }
    redraw.setSingleShot(true);
    redraw.setInterval(100);
    connect(&redraw, &QTimer::timeout, this, &Adapter::updated);
    const bool a = connect(host, SIGNAL(framesSelected(QList<int>)), this, SLOT(framesChanged(QList<int>)),
        Qt::DirectConnection);
    const bool b = connect(
        host, SIGNAL(setCaptureFile(capture_file*)), this, SLOT(captureChanged()), Qt::DirectConnection);
    if (!a || !b) {
        engine.diagnostic = "Unsupported Wireshark UI signals; expected pinned 4.7.4";
        return;
    }
    auto* error = register_tap_listener(
        "frame", this, Extractor::tapFilter().toUtf8().constData(), TL_REQUIRES_PROTO_TREE,
        [](void* data) {
            auto* self = static_cast<Adapter*>(data);
            self->engine.reset();
            emit self->invalidated();
            self->changed();
        },
        [](void* data, packet_info* pi, epan_dissect_t* edt, const void*, tap_flags_t) {
            auto* self = static_cast<Adapter*>(data);
            Q_ASSERT(QThread::currentThread() == self->thread());
            const auto packet = Extractor::copy(edt, pi);
            self->engine.observeFrame(packet.frame, packet.timeMs);
            if (!packet.diagnostic.isEmpty())
                self->engine.diagnostic = packet.diagnostic;
            for (auto event : normalize(packet))
                self->engine.ingest(std::move(event));
            return TAP_PACKET_REDRAW;
        },
        [](void* data) { static_cast<Adapter*>(data)->changed(); }, nullptr);
    if (error) {
        engine.diagnostic = QString::fromUtf8(error->str);
        g_string_free(error, true);
        return;
    }
    epan_set_always_visible(true);
    registered = true;
    QTimer::singleShot(0, this, &Adapter::retap);
}
Adapter::~Adapter()
{
    if (registered) {
        remove_tap_listener(this);
        epan_set_always_visible(false);
    }
}
void Adapter::changed()
{
    if (!redraw.isActive())
        redraw.start();
}
void Adapter::framesChanged(QList<int> frames)
{
    // This revision emits visual row indices despite the signal's name/documentation.
    // Read the authoritative current frame for single selection, never row+1.
    selectedFrames.clear();
    if (frames.size() == 1)
        plugin_if_get_frame_data(
            [](frame_data* frame, void* data) -> void* {
                if (frame)
                    static_cast<Adapter*>(data)->selectedFrames = { int(frame->num) };
                return nullptr;
            },
            this);
    else if (frames.size() > 1 && packetList && packetList->model()) {
        int column = -1;
        for (int i = 0; i < packetList->model()->columnCount(); ++i)
            if (get_column_format(i) == COL_NUMBER) {
                column = i;
                break;
            }
        if (column >= 0)
            for (const auto& position : packetList->selectionModel()->selectedRows(column)) {
                bool ok = false;
                const auto frame = position.data(Qt::DisplayRole).toString().toUInt(&ok);
                if (!ok || !frame) {
                    selectedFrames.clear();
                    break;
                }
                selectedFrames.push_back(int(frame));
            }
        if (selectedFrames.empty())
            engine.diagnostic = "Native multi-selection needs an unaggregated Number column. Select events "
                                "in Semantic Timeline instead.";
    }
    emit selectionChanged();
}
void Adapter::captureChanged()
{
    engine.reset();
    selectedFrames.clear();
    emit invalidated();
    changed();
}
void Adapter::retap()
{
    if (!registered)
        return;
    bool open = false;
    plugin_if_get_capture_file(
        [](capture_file* cf, void* data) -> void* {
            *static_cast<bool*>(data) = cf->state != FILE_CLOSED;
            return nullptr;
        },
        &open);
    if (!open) {
        engine.reset();
        engine.diagnostic = "No capture loaded.";
        changed();
        return;
    }
    auto* ops = funnel_get_funnel_ops();
    if (ops && ops->retap_packets)
        ops->retap_packets(ops->ops_id);
    else
        engine.diagnostic = "Wireshark funnel retap operation unavailable";
    plugin_if_get_capture_file(
        [](capture_file* cf, void* data) -> void* {
            auto* self = static_cast<Adapter*>(data);
            self->captureBoundary = cf->state != FILE_READ_IN_PROGRESS;
            if (self->captureBoundary && cf->count > self->engine.lastFrame)
                self->engine.diagnostic = "Retap did not reach the final capture frame; results are partial.";
            if (cf->current_frame)
                self->selectedFrames = { int(cf->current_frame->num) };
            return nullptr;
        },
        this);
    changed();
}
void Adapter::navigate(quint32 frame)
{
    if (frame)
        plugin_if_goto_frame(frame);
}
void Adapter::filter(const QVector<quint32>& frames)
{
    if (frames.empty())
        return;
    auto sorted = frames;
    std::sort(sorted.begin(), sorted.end());
    QStringList ranges;
    for (int i = 0; i < sorted.size();) {
        auto first = sorted[i], last = first;
        while (++i < sorted.size() && sorted[i] <= last + 1)
            last = sorted[i];
        ranges << (first == last ? QString::number(first) : QString("%1..%2").arg(first).arg(last));
    }
    const auto expression = ("frame.number in {" + ranges.join(", ") + "}").toUtf8();
    plugin_if_apply_filter(expression.constData(), true);
}
}
