// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include "wireshark/Extractor.h"
#include "core/Engine.h"
#include "ai/Sanitizer.h"
#include <epan/epan.h>
#include <epan/prefs.h>
#include <epan/frame_data.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QFile>
#include <deque>
#include <cstdio>
struct FrameStore {
    std::deque<frame_data> frames;
};
static const nstime_t* timestamp(struct packet_provider_data* data, uint32_t n)
{
    auto* store = reinterpret_cast<FrameStore*>(data);
    return n > 0 && n <= store->frames.size() ? &store->frames[n - 1].abs_ts : nullptr;
}
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: semantic_analyze capture.pcap output.json [policy.json]\n");
        return 2;
    }
    sspa::Policy policy;
    if (argc == 4) {
        QFile f(QString::fromLocal8Bit(argv[3]));
        if (!f.open(QIODevice::ReadOnly) || f.size() > 1048576)
            return 2;
        QJsonParseError parse;
        auto doc = QJsonDocument::fromJson(f.readAll(), &parse);
        QString error;
        if (parse.error != QJsonParseError::NoError || !doc.isObject())
            return 2;
        auto parsed = sspa::Policy::parse(doc.object(), error);
        if (!parsed) {
            fprintf(stderr, "Invalid asset policy\n");
            return 2;
        }
        policy = *parsed;
    }
    init_process_policies();
    ws_log_init(nullptr, "Stateful Semantic Protocol Analyzer");
    char* initError = configuration_init(argv[0], "wireshark");
    if (initError) {
        g_free(initError);
        return 2;
    }
    wtap_init(false, "WIRESHARK", nullptr, 0);
    epan_app_data_t application {};
    application.env_var_prefix = "WIRESHARK";
    application.register_func = register_all_protocols;
    application.handoff_func = register_all_protocol_handoffs;
    if (!epan_init(nullptr, nullptr, false, &application))
        return 2;
    epan_load_settings();
    prefs_apply_all();
    const auto missing = sspa::Extractor::missingFields();
    for (const auto& name : missing)
        fprintf(stderr, "Unavailable semantic field: %s\n", qPrintable(name));
    int error = 0;
    char* errorInfo = nullptr;
    wtap* capture = wtap_open_offline(argv[1], WTAP_TYPE_AUTO, &error, &errorInfo, false, "WIRESHARK");
    if (!capture) {
        g_free(errorInfo);
        return 2;
    }
    FrameStore store;
    packet_provider_funcs funcs {};
    funcs.get_frame_ts = timestamp;
    funcs.get_start_ts = [](packet_provider_data* data) -> const nstime_t* { return timestamp(data, 1); };
    epan_t* session = epan_new(reinterpret_cast<packet_provider_data*>(&store), &funcs);
    wtap_rec record;
    wtap_rec_init(&record, 65536);
    int64_t offset = 0;
    uint32_t count = 0;
    nstime_t elapsed {};
    const frame_data* reference = nullptr;
    const frame_data* previous = nullptr;
    sspa::Engine engine(policy);
    while (wtap_read(capture, &record, &error, &errorInfo, &offset)) {
        store.frames.emplace_back();
        auto& frame = store.frames.back();
        frame_data_init(&frame, ++count, &record, offset, 0);
        frame_data_set_before_dissect(&frame, &elapsed, &reference, previous);
        auto* edt = epan_dissect_new(session, true, true);
        epan_dissect_run(edt, wtap_file_type_subtype(capture), &record, &frame, nullptr);
        const auto copied = sspa::Extractor::copy(edt, &edt->pi);
        epan_dissect_free(
            edt); // Normalization and state processing cannot depend on transient dissection memory.
        engine.observeFrame(copied.frame, copied.timeMs);
        if (!copied.diagnostic.isEmpty())
            engine.diagnostic = copied.diagnostic;
        for (auto event : sspa::normalize(copied))
            engine.ingest(std::move(event));
        previous = &frame;
        wtap_rec_reset(&record);
    }
    auto report = sspa::localReport(engine, true);
    report["capture_frames"] = qint64(count);
    sspa::Sanitizer sanitizer;
    report["semantic_context"] = sanitizer.build(sspa::buildContext(engine, {})).json;
    epan_free(session);
    for (auto& frame : store.frames)
        frame_data_destroy(&frame);
    wtap_rec_cleanup(&record);
    wtap_close(capture);
    epan_cleanup();
    wtap_cleanup();
    free_progdirs();
    if (error) {
        g_free(errorInfo);
        return 2;
    }
    QFile output(QString::fromLocal8Bit(argv[2]));
    if (!output.open(QIODevice::WriteOnly))
        return 2;
    output.write(QJsonDocument(report).toJson());
    return 0;
}
