// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include "WiresharkAdapter.h"
#include "ProtoTreeExtractor.h"
#include <ui/plugins/include/plugin_if.h>
#include <epan/cfile.h>
#include <QTimer>
#include <QThread>
namespace pv
{
WiresharkAdapter::WiresharkAdapter(QWidget* host, PacketViewerWidget* v)
    : QObject(v)
    , viewer(v)
{
    // Public QObject signals, avoiding binary linkage to executable-owned Qt classes.
    const auto frames = connect(host, SIGNAL(framesSelected(QList<int>)), this,
        SLOT(framesChanged(QList<int>)), Qt::DirectConnection);
    const auto capture = connect(
        host, SIGNAL(setCaptureFile(capture_file*)), this, SLOT(captureChanged()), Qt::DirectConnection);
    const auto field = connect(
        host, SIGNAL(fieldSelected(FieldInformation*)), this, SLOT(fieldChanged()), Qt::DirectConnection);
    if (!frames || !capture || !field) {
        viewer->showDiagnostic("Wireshark UI signal interface incompatible; expected pinned 4.7.4");
        return;
    }
    refresh();
}
void WiresharkAdapter::framesChanged(QList<int> frames)
{
    multiple = frames.size() != 1;
    if (multiple) {
        ++generation;
        viewer->showDiagnostic(frames.empty() ? "No packet selected." : "Select exactly one packet.");
    } else
        refresh();
}
void WiresharkAdapter::captureChanged()
{
    ++generation;
    viewer->showDiagnostic("No capture loaded.");
    // Never retain the signal's capture pointer; retrieve the current capture on the GUI thread.
    QTimer::singleShot(0, this, &WiresharkAdapter::refresh);
}
void WiresharkAdapter::refresh()
{
    Q_ASSERT(QThread::currentThread() == thread());
    struct Context {
        Packet packet;
        uint64_t generation;
    } context { {}, ++generation };
    plugin_if_get_capture_file(
        [](capture_file* cf, void* data) -> void* {
            auto& c = *static_cast<Context*>(data);
            if (cf->state == FILE_CLOSED)
                return nullptr;
            if (!cf->current_frame)
                return nullptr;
            auto* frame = cf->current_frame;
            c.packet = ProtoTreeExtractor::extract(
                cf->edt, frame->num, frame->cap_len, frame->pkt_len, cf->lnk_t, c.generation);
            return nullptr;
        },
        &context);
    if (context.packet && !multiple)
        viewer->setPacket(std::move(context.packet));
    else if (!context.packet)
        viewer->showDiagnostic("No capture loaded or no packet selected.");
}
void WiresharkAdapter::fieldChanged()
{
    QTimer::singleShot(0, this, &WiresharkAdapter::syncField);
}
void WiresharkAdapter::syncField()
{
    if (!viewer->model || multiple)
        return;
    struct Context {
        const PacketModel* model;
        int id = -1;
    } context { viewer->model.get() };
    plugin_if_get_capture_file(
        [](capture_file* cf, void* data) -> void* {
            auto& c = *static_cast<Context*>(data);
            if (!cf->current_frame || cf->current_frame->num != c.model->frame || !cf->edt || !cf->edt->tree
                || !cf->finfo_selected)
                return nullptr;
            // Compare live pointers only inside this callback, map traversal index to copied local ID.
            QVector<proto_node*> pending;
            if (cf->edt->tree->first_child)
                pending.push_back(cf->edt->tree->first_child);
            int id = 0;
            while (!pending.empty() && id < c.model->fields.size()) {
                auto* n = pending.takeLast();
                if (n->next)
                    pending.push_back(n->next);
                if (n->finfo && n->finfo->hfinfo) {
                    if (n->finfo == cf->finfo_selected && n->finfo->hfinfo->id == c.model->fields[id].hfId) {
                        c.id = id;
                        break;
                    }
                    ++id;
                }
                if (n->first_child)
                    pending.push_back(n->first_child);
            }
            return nullptr;
        },
        &context);
    if (context.id >= 0)
        viewer->selectField(context.id);
}
}
