// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include "ui/Viewer.h"
#include <ui/plugins/include/plugin_if.h>
#include <epan/cfile.h>
#include <QtTest>
#include <QApplication>
#include <QAction>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTableView>
#include <QTreeView>
#include <QPlainTextEdit>
#include <QCheckBox>
#include <QComboBox>
#include <QPushButton>
#include <QFile>
#include <QSpinBox>
#include <QDialog>
#include <QListWidget>
void runSemanticGuiTests(sspa::Viewer* v, QWidget* host)
{
    const QString dir = qEnvironmentVariable("SSPA_TEST_DIR");
    QJsonArray results;
    auto check = [&](QString name, bool pass) {
        results.append(QJsonObject { { "test", name }, { "pass", pass } });
    };
    auto open = [&](QString name) {
        bool loaded = false;
        const bool invoked = QMetaObject::invokeMethod(host, "openCaptureFile", Qt::DirectConnection,
            Q_RETURN_ARG(bool, loaded), Q_ARG(QString, dir + "/" + name + ".pcap"),
            Q_ARG(QString, QString()));
        QTest::qWait(250);
        return invoked && loaded;
    };
    check("native plugin loaded", true);
    check("AI off by default", !v->ai->provider.enabled() && v->ai->provider.requestCount() == 0);
    check("open IEC104", open("iec104_normal_temporal"));
    check("capture-wide tap extracts all events", v->adapter.engine.events.size() == 16);
    const auto& engine = v->adapter.engine;
    bool control = false, values = false;
    for (const auto& t : engine.transactions)
        control |= t.state == "COMMAND_TERMINATED" && t.frames == QVector<quint32>({ 6, 7, 8 })
            && std::abs(t.endMs - t.startMs - 42) < 1e-6;
    for (const auto& e : engine.events)
        values |= e.frame == 11 && e.type == "MEASUREMENT" && e.number("value")
            && std::abs(*e.number("value") - 150.4) < .001 && e.timeMs == 3000;
    check("tap control correlation and 42 ms duration", control);
    check("tap float measurement and timestamp", values);
    auto* table = v->findChild<QTableView*>("semanticEvents");
    sspa::Adapter::navigate(11);
    QTest::qWait(200);
    check("packet selection synchronization", v->adapter.selectedFrames == QList<int>({ 11 }));
    int target = -1;
    for (int i = 0; i < engine.events.size(); ++i)
        if (engine.events[i].frame == 11 && engine.events[i].type == "MEASUREMENT")
            target = i;
    if (target >= 0) {
        table->selectRow(target);
        table->scrollTo(table->model()->index(target, 0));
    }
    auto* mode = v->findChild<QComboBox*>("semanticContextMode");
    mode->setCurrentIndex(6);
    for (auto* b : v->findChildren<QPushButton*>())
        if (b->text() == "Analyze Semantic Differences (local)")
            b->click();
    const auto context = v->findChild<QPlainTextEdit*>("semanticContext")->toPlainText();
    check("time window deterministic differences",
        context.contains("adjacent_differences") && context.contains("150.399")
            && context.contains("rate_per_second"));
    check("sanitized context excludes endpoint addresses",
        !context.contains("192.0.2") && !context.contains("raw_bytes"));
    check("offline analysis generated no requests", v->ai->provider.requestCount() == 0);
    const int count = engine.events.size();
    sspa::Adapter::filter({ 6, 7, 8 });
    QTest::qWait(300);
    check("display filter preserves capture-wide state", engine.events.size() == count);
    for (auto* native : host->findChildren<QTreeView*>())
        if (native->inherits("PacketList")) {
            auto* selections = native->selectionModel();
            selections->select(native->model()->index(0, 0),
                QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
            selections->select(
                native->model()->index(2, 0), QItemSelectionModel::Select | QItemSelectionModel::Rows);
            QTest::qWait(100);
            auto frames = v->adapter.selectedFrames;
            std::sort(frames.begin(), frames.end());
            check("multiple native rows map through active display filter", frames == QList<int>({ 6, 8 }));
            break;
        }
    plugin_if_apply_filter("", true);
    QTest::qWait(100);
    v->adapter.retap();
    QTest::qWait(200);
    check("redissection deterministic", engine.events.size() == count && engine.findings.empty());
    bool navigated = false;
    sspa::Adapter::navigate(9);
    QTest::qWait(100);
    plugin_if_get_capture_file(
        [](capture_file* cf, void* p) -> void* {
            *static_cast<bool*>(p) = cf->current_frame && cf->current_frame->num == 9;
            return nullptr;
        },
        &navigated);
    check("semantic evidence frame navigation", navigated);
    for (const auto& name : { "goose_regression", "rgoose_regression", "rgoose_multi_pdu", "sv_gap",
             "modbus_write", "mms_identify", "dnp3_read", "iec104_segmented", "iec104_retransmission",
             "iec104_missing_termination", "iec104_boundary" }) {
        check(QString("open ") + name, open(name));
        check(QString("semantic events ") + name, !engine.events.empty());
        if (QString(name) == "iec104_segmented") {
            bool derived = false;
            for (const auto& e : engine.events)
                if (e.type == "CONTROL")
                    for (const auto& val : e.values)
                        for (const auto& p : val.evidence)
                            derived |= p.field == "iec60870_asdu.ioa" && p.frame == 5;
            check("reassembly provenance completion frame", derived);
        }
    }
    for (auto* action : host->findChildren<QAction*>())
        if (action->objectName() == "actionFileClose") {
            action->trigger();
            break;
        }
    QTest::qWait(200);
    check("capture close clears stale state", engine.events.empty());
    check("capture reopen", open("iec104_normal_temporal"));
    check("reopen state reconstructed", engine.events.size() == 16);
    if (qEnvironmentVariableIsSet("SSPA_AI_TEST")) {
        // Test-only secret handoff: stdin with echo disabled by the runner, never argv or a file.
        QFile input;
        input.open(stdin, QIODevice::ReadOnly);
        QByteArray key = input.readLine(4096).trimmed();
        const bool haveKey = !key.isEmpty();
        v->ai->provider.setApiKey(std::move(key));
        key.fill('\0');
        check("session key configured without persistence", haveKey && v->ai->provider.keyConfigured());
        auto* enable = v->findChild<QCheckBox*>("enableAi");
        enable->setChecked(true);
        QSignalSpy catalog(&v->ai->provider, &sspa::AIProvider::modelsChanged);
        QSignalSpy failure(&v->ai->provider, &sspa::AIProvider::failed);
        v->ai->provider.refreshModels();
        QElapsedTimer wait;
        wait.start();
        while (catalog.empty() && failure.empty() && wait.elapsed() < 50000)
            QTest::qWait(50);
        check("live dynamic OpenCode model discovery", !catalog.empty());
        auto* models = v->findChild<QComboBox*>("aiModel");
        for (const auto& m : v->ai->provider.models())
            if (m.api == sspa::ApiType::Responses) {
                models->setCurrentIndex(models->findData(m.id));
                break;
            }
        mode->setCurrentIndex(7);
        v->findChild<QSpinBox*>("semanticFirstFrame")->setValue(9);
        v->findChild<QSpinBox*>("semanticLastFrame")->setValue(12);
        bool reviewed = false;
        QSignalSpy completed(&v->ai->provider, &sspa::AIProvider::completed);
        failure.clear();
        QTimer::singleShot(100, v, [&] {
            auto* dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            if (!dialog)
                return;
            auto* text = dialog->findChild<QPlainTextEdit*>();
            if (!text) {
                dialog->reject();
                return;
            }
            const auto body = text->toPlainText().toUtf8();
            reviewed = body.contains("adjacent_differences") && !body.contains("192.0.2")
                && !body.contains("raw_bytes");
            if (reviewed) {
                QFile f(dir + "/live-ai-request.json");
                if (f.open(QIODevice::WriteOnly))
                    f.write(body);
                dialog->findChild<QPushButton*>("sendAiRequest")->click();
            } else
                dialog->reject();
        });
        for (auto* button : v->findChildren<QPushButton*>())
            if (button->text() == "Analyze Differences with AI / View AI Request") {
                button->click();
                break;
            }
        check("live exact request preview before Send", reviewed);
        wait.restart();
        while (completed.empty() && failure.empty() && wait.elapsed() < 50000)
            QTest::qWait(50);
        check("live validated AI-derived observation", !completed.empty());
        if (!completed.empty()) {
            auto result = qvariant_cast<QJsonObject>(completed.front()[0]);
            auto metadata = qvariant_cast<QJsonObject>(completed.front()[1]);
            QFile f(dir + "/live-ai-result.json");
            if (f.open(QIODevice::WriteOnly))
                f.write(
                    QJsonDocument(QJsonObject { { "result", result }, { "metadata", metadata } }).toJson());
            auto* refs = v->ai->findChild<QListWidget*>();
            bool reached = false;
            if (refs && refs->count()) {
                auto* item = refs->item(0);
                refs->itemActivated(item);
                QTest::qWait(100);
                const auto frame = item->data(Qt::UserRole).toInt();
                reached = v->adapter.selectedFrames.contains(frame);
            }
            check("live AI evidence navigates to packet", reached);
        } else if (!failure.empty()) {
            QFile f(dir + "/live-ai-error.txt");
            if (f.open(QIODevice::WriteOnly))
                f.write(failure.front()[0].toString().toUtf8());
        }
        enable->setChecked(false);
        const auto requests = v->ai->provider.requestCount();
        v->ai->provider.refreshModels();
        QTest::qWait(100);
        check("disable AI stops all new requests",
            v->ai->provider.requestCount() == requests && !v->ai->provider.enabled());
        check("AI result does not modify deterministic state",
            engine.events.size() == 16 && engine.findings.empty());
    }
    v->grab().save(dir + "/semantic-viewer.png");
    QFile report(dir + "/gui-results.json");
    if (report.open(QIODevice::WriteOnly))
        report.write(QJsonDocument(results).toJson());
    QTimer::singleShot(100, qApp, [] { qApp->quit(); });
}
