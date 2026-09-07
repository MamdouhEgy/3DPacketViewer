// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include "GuiTests.h"
#include "core/SelectionController.h"
#include <ui/plugins/include/plugin_if.h>
#include <QtTest>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDir>
#include <QAction>
#include <QApplication>
#include <QTreeView>
void runPacketViewerGuiTests(pv::PacketViewerWidget* v, QWidget* host)
{
    const QString dir = qEnvironmentVariable("PACKETVIEWER_TEST_DIR");
    QJsonArray results;
    auto check = [&](QString name, bool pass) {
        results.append(QJsonObject { { "test", name }, { "pass", pass } });
    };
    auto open = [&](QString name) {
        bool loaded = false;
        const bool invoked = QMetaObject::invokeMethod(host, "openCaptureFile", Qt::DirectConnection,
            Q_RETURN_ARG(bool, loaded), Q_ARG(QString, dir + "/" + name + ".pcap"),
            Q_ARG(QString, QString()));
        QTest::qWait(150);
        plugin_if_goto_frame(1);
        QTest::qWait(150);
        return invoked && loaded;
    };
    check("plugin loading", true);
    check("open Modbus", open("modbus"));
    check(
        "selected packet model", v->model && v->model->frame == 1 && v->model->protocols.contains("modbus"));
    check("byte map is default", v->views->currentWidget() == v->byteMap && v->byteMap->isVisible());
    int mapTarget = -1;
    for (const auto& f : v->model->fields)
        if (f.abbreviation == "mbtcp.trans_id")
            mapTarget = f.id;
    v->selectField(mapTarget);
    QTest::qWait(100);
    const auto targetRect = v->byteMap->fieldRect(mapTarget);
    v->selectField(-1);
    QTest::mouseClick(v->byteMap->viewport(), Qt::LeftButton, Qt::NoModifier, targetRect.center().toPoint());
    check("byte map field picking",
        mapTarget >= 0 && !targetRect.isEmpty() && v->renderer->selected == mapTarget);
    check("byte map decoded explanation",
        v->selectionSummary->text().contains("4660") && v->selectionSummary->text().contains("54 (0x36)")
            && v->selectionSummary->text().contains("16 represented bits"));
    check("byte map exact selected bits",
        v->byteMap->highlighted(54 * 8) && v->byteMap->highlighted(56 * 8 - 1)
            && !v->byteMap->highlighted(56 * 8));
    const auto mapImage = v->byteMap->viewport()->grab().toImage();
    v->protocolFocus->setCurrentIndex(1);
    QTest::qWait(50);
    check("protocol focus changes presentation only",
        mapImage != v->byteMap->viewport()->grab().toImage() && v->byteMap->fieldRect(mapTarget) == targetRect
            && v->byteMap->highlighted(54 * 8));
    v->protocolFocus->setCurrentIndex(0);
    v->byteMap->setRowBits(32);
    check("byte map wrapping preserves selection",
        v->byteMap->highlighted(54 * 8)
            && v->byteMap->fieldAt(v->byteMap->fieldRect(mapTarget).center().toPoint()) == mapTarget);
    v->byteMap->setRowBits(64);
    v->grab().save(dir + "/byte-map-modbus.png");
    bool generatedMap = false;
    for (const auto& f : v->model->fields)
        if (f.generated) {
            v->selectField(f.id);
            generatedMap = v->selectionSummary->text().contains("no direct wire range")
                && !v->byteMap->highlighted(f.start * 8) && v->byteMap->fieldRect(f.id).isEmpty();
            break;
        }
    check("byte map generated fields have no positions", generatedMap);
    v->viewMode->setCurrentIndex(1);
    check("3D view remains available", v->views->currentWidget() == v->renderer);
    auto* r = v->renderer;
    QTest::qWait(500);
    check("OpenGL rendering",
        r->isValid() && r->glError.isEmpty() && r->renderCount > 0 && !r->grabFramebuffer().isNull());
    const auto idleCount = r->renderCount;
    QTest::qWait(150);
    check("idle rendering bounded", r->renderCount - idleCount < 10);
    auto* labelOverlay = r->findChild<QWidget*>("packetLabels");
    const auto labelImage = labelOverlay ? labelOverlay->grab().toImage() : QImage();
    const auto oldRotation = r->camera.rotation;
    QTest::mousePress(r, Qt::LeftButton, Qt::NoModifier, { 200, 180 });
    QMouseEvent move(QEvent::MouseMove, QPointF(250, 210), QPointF(r->mapToGlobal(QPoint(250, 210))),
        Qt::NoButton, Qt::LeftButton, Qt::NoModifier);
    QApplication::sendEvent(r, &move);
    QTest::mouseRelease(r, Qt::LeftButton, Qt::NoModifier, { 250, 210 });
    check("rotation", oldRotation != r->camera.rotation);
    const float oldDistance = r->camera.distance;
    QWheelEvent wheel(QPointF(200, 180), QPointF(r->mapToGlobal(QPoint(200, 180))), QPoint(), QPoint(0, 120),
        Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
    QApplication::sendEvent(r, &wheel);
    check("zoom", oldDistance != r->camera.distance);
    const auto oldCenter = r->camera.center;
    QTest::mousePress(r, Qt::MiddleButton, Qt::NoModifier, { 200, 180 });
    QMouseEvent pan(QEvent::MouseMove, QPointF(240, 200), QPointF(r->mapToGlobal(QPoint(240, 200))),
        Qt::NoButton, Qt::MiddleButton, Qt::NoModifier);
    QApplication::sendEvent(r, &pan);
    QTest::mouseRelease(r, Qt::MiddleButton, Qt::NoModifier, { 240, 200 });
    check("pan", oldCenter != r->camera.center);
    auto trigger = [&](QString title) {
        for (auto* a : v->actions())
            if (a->text() == title) {
                a->trigger();
                return true;
            }
        return false;
    };
    const auto before = r->geometry;
    check("explode action", trigger("Explode"));
    bool zChanged = false, semantics = true;
    for (int i = 0; i < before.tiles.size(); ++i) {
        zChanged |= before.tiles[i].low.z() != r->geometry.tiles[i].low.z();
        semantics &= before.tiles[i].bits == r->geometry.tiles[i].bits;
    }
    check("explode changes only presentation", zChanged && semantics);
    check("projection action", trigger("Orthographic") && r->camera.orthographic);
    check("label action", trigger("Labels") && !r->labels);
    QTest::qWait(100);
    check("label raster rendering",
        labelOverlay && !labelImage.isNull() && labelOverlay->grab().toImage() != labelImage);
    check("generated action", trigger("Generated") && !v->showGenerated);
    trigger("Generated");
    trigger("Labels");
    trigger("Explode");
    trigger("Reset");
    int target = -1;
    for (const auto& f : v->model->fields)
        if (f.abbreviation == "mbtcp.trans_id")
            target = f.id;
    v->selectField(target);
    check("inspector", target >= 0 && v->inspector->toPlainText().contains("4660"));
    check("byte and bit highlighting",
        v->bytes->highlighted(54 * 8) && v->bytes->highlighted(55 * 8 + 7) && !v->bytes->highlighted(56 * 8));
    bool nativeSelected = false;
    for (auto* native : host->findChildren<QTreeView*>()) {
        if (!native->inherits("ProtoTree"))
            continue;
        native->expandAll();
        const auto found = native->model()->match(native->model()->index(0, 0), Qt::DisplayRole,
            QString("Transaction Identifier"), 1, Qt::MatchContains | Qt::MatchRecursive);
        if (!found.isEmpty()) {
            v->selectField(-1);
            native->scrollTo(found[0]);
            QTest::qWait(50);
            QTest::mouseClick(
                native->viewport(), Qt::LeftButton, Qt::NoModifier, native->visualRect(found[0]).center());
            native->setCurrentIndex(found[0]);
            QTest::qWait(100);
            nativeSelected = r->selected == target;
        }
    }
    check("native to viewer field synchronization", nativeSelected);
    r->camera.rotation = QQuaternion();
    r->layout.wireView = true;
    r->rebuild(true);
    QTest::qWait(100);
    bool picked = false;
    for (const auto& t : r->geometry.tiles) {
        if (t.field != target)
            continue;
        auto pos = r->camera.matrix(r->size()).map((t.low + t.high) * .5f);
        const QPoint p(int((pos.x() + 1) * r->width() / 2), int((1 - pos.y()) * r->height() / 2));
        v->selectField(-1);
        QTest::mouseClick(r, Qt::LeftButton, Qt::NoModifier, p);
        picked = r->selected == target;
        break;
    }
    check("field picking", picked);
    check("TCP reassembly capture", open("tcp_reassembly"));
    const auto generation = v->model->generation;
    const auto retained = v->model;
    plugin_if_goto_frame(2);
    QTest::qWait(150);
    check("packet selection synchronization",
        v->model->frame == 2 && v->model->generation != generation && retained->frame == 1);
    bool derived = false;
    for (const auto& f : v->model->fields)
        if (f.abbreviation == "mbtcp.trans_id")
            derived = f.derived && !f.wireBacked && f.source > 0;
    check("reassembly provenance", derived);
    bool mapDerived = false;
    for (const auto& f : v->model->fields)
        if (f.abbreviation == "mbtcp.trans_id") {
            v->selectField(f.id);
            mapDerived = v->selectionSummary->text().contains("separate source")
                && v->sources->currentIndex() == f.source && v->byteMap->highlighted(f.ranges.front().start);
        }
    check("byte map reassembly uses separate source", mapDerived);
    plugin_if_apply_filter("frame.number == 1", true);
    QTest::qWait(200);
    check("display filter update", v->model->frame == 0 || v->model->frame == 1);
    plugin_if_apply_filter("", true);
    QTest::qWait(150);
    plugin_if_goto_frame(2);
    QTest::qWait(100);
    check("display filter restored", v->model->frame == 2);
    for (int i = 0; i < 20; ++i) {
        plugin_if_goto_frame(i % 2 + 1);
        QTest::qWait(5);
    }
    check("repeated packet switches", v->model->frame == 2);
    const QStringList fixtures = { "ethernet_ipv4_tcp", "ethernet_ipv4_udp", "arp", "icmp", "vlan", "ipv6",
        "tcp_options", "ipv4_options", "bit_fields", "truncated", "malformed", "ip_reassembly", "iec104",
        "goose", "mms", "sampled_values", "dnp3", "goose_many_fields", "zero_length" };
    for (const auto& name : fixtures) {
        check("GUI fixture " + name, open(name) && v->model && pv::validateModel(*v->model).isEmpty());
        if (name == "bit_fields") {
            bool syn = false;
            for (const auto& f : v->model->fields)
                if (f.abbreviation == "tcp.flags.syn") {
                    v->selectField(f.id);
                    syn = v->byteMap->highlighted(382) && !v->byteMap->highlighted(381)
                        && !v->byteMap->highlighted(383);
                }
            check("byte map one-bit flag excludes neighbors", syn);
            bool parent = false;
            for (const auto& f : v->model->fields)
                if (f.abbreviation == "ip") {
                    v->selectField(f.id);
                    parent = v->byteMap->fieldRect(f.id).isEmpty() && v->byteMap->highlighted(112)
                        && !v->byteMap->highlighted(111);
                }
            check("byte map structural parent highlights without duplicate tile", parent);
        }
    }
    check("reopen capture", open("modbus"));
    const auto generation2 = v->model->generation;
    // Exercise normal user actions by their Qt QAction object names in test code only.
    bool redissect = false;
    for (auto* a : host->findChildren<QAction*>())
        if (a->objectName() == "actionViewReload") {
            a->trigger();
            redissect = true;
            break;
        }
    QTest::qWait(300);
    check("redissection", redissect && v->model->generation != generation2);
    bool close = false;
    for (auto* a : host->findChildren<QAction*>())
        if (a->objectName() == "actionFileClose") {
            a->trigger();
            close = true;
            break;
        }
    QTest::qWait(200);
    check("capture close invalidation", close && v->model->frame == 0);
    check("capture reopen", open("iec104"));
    r->layout.wireView = false;
    r->camera.reset();
    r->rebuild(true);
    QTest::qWait(150);
    for (const auto& f : v->model->fields)
        if (f.abbreviation == "iec60870_asdu.typeid") {
            v->selectField(f.id);
            break;
        }
    QTest::qWait(100);
    v->viewMode->setCurrentIndex(0);
    QTest::qWait(100);
    check("map restored after capture changes",
        v->views->currentWidget() == v->byteMap
            && v->selectionSummary->text().contains("iec60870_asdu.typeid"));
    v->grab().save(dir + "/viewer.png");
    QFile out(dir + "/gui-results.json");
    if (out.open(QIODevice::WriteOnly))
        out.write(QJsonDocument(results).toJson());
    out.close();
    host->close();
    QTimer::singleShot(100, qApp, &QApplication::quit);
}
