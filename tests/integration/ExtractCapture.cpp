// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include "wireshark/ProtoTreeExtractor.h"
#include "core/PacketGeometryEngine.h"
#include <epan/epan.h>
#include <epan/prefs.h>
#include <epan/frame_data.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <cstdio>
static const nstime_t* timestamp(struct packet_provider_data*, uint32_t)
{
    static nstime_t t {};
    return &t;
}
static QJsonObject encode(const pv::PacketModel& m)
{
    QJsonArray sources, fields, tiles;
    for (const auto& s : m.sources)
        sources.append(QJsonObject { { "name", s.name }, { "captured", qint64(s.captured) },
            { "reported", qint64(s.reported) }, { "current", s.currentFrame },
            { "hex", QString::fromLatin1(s.bytes.toHex()) } });
    for (const auto& f : m.fields) {
        QJsonArray ranges;
        for (auto r : f.ranges)
            ranges.append(QJsonArray { qint64(r.start), qint64(r.length) });
        fields.append(QJsonObject { { "id", f.id }, { "parent", f.parent }, { "abbr", f.abbreviation },
            { "protocol", f.protocol }, { "start", qint64(f.start) }, { "length", qint64(f.length) },
            { "bit_offset", int(f.bitOffset) }, { "bit_size", int(f.bitSize) },
            { "mask", QString::number(f.mask, 16) }, { "source", f.source }, { "generated", f.generated },
            { "hidden", f.hidden }, { "wire", f.wireBacked }, { "derived", f.derived }, { "exact", f.exact },
            { "ranges", ranges }, { "value", f.rawValue }, { "display", f.display } });
    }
    double geometryMs = 0;
    for (int source = 0; source < m.sources.size(); ++source) {
        pv::Layout l;
        l.source = source;
        const auto g = pv::PacketGeometryEngine::build(m, l);
        geometryMs += g.buildMs;
        for (const auto& t : g.tiles)
            tiles.append(QJsonObject { { "field", t.field }, { "source", t.source },
                { "start", qint64(t.bits.start) }, { "length", qint64(t.bits.length) } });
    }
    return { { "frame", int(m.frame) }, { "captured", qint64(m.captured) },
        { "reported", qint64(m.reported) }, { "sources", sources }, { "fields", fields }, { "tiles", tiles },
        { "extraction_ms", m.extractionMs }, { "geometry_ms", geometryMs }, { "diagnostic", m.diagnostic } };
}
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 3) {
        fprintf(stderr, "usage: packetviewer_extract capture.pcap output.json\n");
        return 2;
    }
    init_process_policies();
    ws_log_init(nullptr, "3DPacketViewer validation");
    char* error = configuration_init(argv[0], "wireshark");
    if (error) {
        fprintf(stderr, "%s\n", error);
        g_free(error);
        return 2;
    }
    wtap_init(false, "WIRESHARK", nullptr, 0);
    epan_app_data_t data {};
    data.env_var_prefix = "WIRESHARK";
    data.register_func = register_all_protocols;
    data.handoff_func = register_all_protocol_handoffs;
    if (!epan_init(nullptr, nullptr, false, &data))
        return 2;
    epan_load_settings();
    prefs_apply_all();
    int err = 0;
    char* info = nullptr;
    wtap* capture = wtap_open_offline(argv[1], WTAP_TYPE_AUTO, &err, &info, false, "WIRESHARK");
    if (!capture) {
        fprintf(stderr, "Capture open failed: %d %s\n", err, info ? info : "");
        g_free(info);
        return 2;
    }
    packet_provider_funcs functions {};
    functions.get_frame_ts = timestamp;
    epan_t* session = epan_new(nullptr, &functions);
    wtap_rec rec;
    wtap_rec_init(&rec, 65536);
    int64_t offset = 0;
    uint32_t frame = 0;
    QJsonArray packets;
    while (wtap_read(capture, &rec, &err, &info, &offset)) {
        frame_data fd;
        frame_data_init(&fd, ++frame, &rec, offset, 0);
        auto* edt = epan_dissect_new(session, true, true);
        epan_dissect_run(edt, wtap_file_type_subtype(capture), &rec, &fd, nullptr);
        const auto model = pv::ProtoTreeExtractor::extract(
            edt, frame, fd.cap_len, fd.pkt_len, rec.rec_header.packet_header.pkt_encap, frame);
        epan_dissect_free(edt);
        frame_data_destroy(&fd);
        wtap_rec_reset(&rec);
        // Intentionally validate and build geometry AFTER dissection lifetime ends.
        const auto invalid = pv::validateModel(*model);
        if (!invalid.isEmpty()) {
            fprintf(stderr, "%s\n", qPrintable(invalid));
            return 1;
        }
        packets.append(encode(*model));
    }
    wtap_rec_cleanup(&rec);
    epan_free(session);
    wtap_close(capture);
    epan_cleanup();
    wtap_cleanup();
    free_progdirs();
    if (err) {
        fprintf(stderr, "Capture read failed: %d\n", err);
        g_free(info);
        return 2;
    }
    QFile output(QString::fromLocal8Bit(argv[2]));
    if (!output.open(QIODevice::WriteOnly))
        return 2;
    output.write(QJsonDocument(packets).toJson());
    return 0;
}
