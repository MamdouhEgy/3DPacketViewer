// SPDX-License-Identifier: GPL-2.0-or-later
#include "Normalizer.h"
#include <QCryptographicHash>
namespace sspa
{
const QMap<QString, QString>& semanticFields()
{
    static const QMap<QString, QString> fields = { { "frame.number", "frame_number" },
        { "exported_pdu.ipv4_src", "source_ip" }, { "exported_pdu.ipv4_dst", "destination_ip" },
        { "exported_pdu.ipv6_src", "source_ip" }, { "exported_pdu.ipv6_dst", "destination_ip" },
        { "ip.src", "source_ip" }, { "ip.dst", "destination_ip" }, { "ipv6.src", "source_ip" },
        { "ipv6.dst", "destination_ip" }, { "eth.src", "source_mac" }, { "eth.dst", "destination_mac" },
        { "tcp.srcport", "source_port" }, { "tcp.dstport", "destination_port" },
        { "tcp.stream", "tcp_stream" }, { "tcp.analysis.retransmission", "retransmission" },
        { "tcp.analysis.fast_retransmission", "retransmission" },
        { "tcp.analysis.spurious_retransmission", "retransmission" },
        { "tcp.analysis.out_of_order", "reordered" }, { "vlan.id", "vlan" },
        { "vlan.priority", "vlan_priority" }, { "_ws.malformed", "malformed" },
        { "iec60870_104.type", "apci_type" }, { "iec60870_104.utype", "utype" }, { "iec60870_104.tx", "tx" },
        { "iec60870_104.rx", "rx" }, { "iec60870_asdu.typeid", "type_id" },
        { "iec60870_asdu.causetx", "cot" }, { "iec60870_asdu.addr", "common_address" },
        { "iec60870_asdu.ioa", "ioa" }, { "iec60870_asdu.nega", "negative" },
        { "iec60870_asdu.test", "test" }, { "iec60870_asdu.float", "value" },
        { "iec60870_asdu.normval", "value" }, { "iec60870_asdu.scalval", "value" },
        { "iec60870_asdu.bcr.count", "value" }, { "iec60870_asdu.siq.spi", "value" },
        { "iec60870_asdu.diq.dpi", "value" }, { "iec60870_asdu.sco.on", "command_value" },
        { "iec60870_asdu.dco.on", "command_value" }, { "iec60870_asdu.sco.se", "select" },
        { "iec60870_asdu.dco.se", "select" }, { "iec60870_asdu.qos.se", "select" },
        { "iec60870_asdu.qds", "quality" }, { "iec60870_asdu.siq", "quality" },
        { "iec60870_asdu.diq", "quality" }, { "iec60870_asdu.sco.qu", "qualifier" },
        { "iec60870_asdu.dco.qu", "qualifier" }, { "iec60870_asdu.cp56time", "protocol_time" },
        { "goose.appid", "app_id" }, { "goose.gocbRef", "control_block" }, { "goose.datSet", "dataset" },
        { "goose.goID", "go_id" }, { "goose.confRev", "conf_rev" }, { "goose.stNum", "st_num" },
        { "goose.sqNum", "sq_num" }, { "goose.timeAllowedtoLive", "ttl_ms" }, { "goose.t", "protocol_time" },
        { "goose.simulation", "simulation" }, { "goose.ndsCom", "needs_commissioning" },
        { "goose.boolean", "dataset_value" }, { "goose.integer", "dataset_value" },
        { "goose.unsigned", "dataset_value" }, { "goose.float_value", "dataset_value" },
        { "sv.appid", "app_id" }, { "sv.svID", "sv_id" }, { "sv.datSet", "dataset" },
        { "sv.confRev", "conf_rev" }, { "sv.smpCnt", "sample_count" }, { "sv.smpSynch", "sample_sync" },
        { "sv.smpRate", "sample_rate" }, { "sv.smpMod", "sample_mode" }, { "sv.meas_value", "value" },
        { "sv.meas_quality", "quality" }, { "sv.refrTm", "protocol_time" }, { "mms.invokeID", "invoke_id" },
        { "mms.confirmedServiceRequest", "service" }, { "mms.confirmedServiceResponse", "service" },
        { "mms.confirmed_RequestPDU_element", "request_marker" },
        { "mms.confirmed_ResponsePDU_element", "response_marker" },
        { "mms.confirmed_ErrorPDU_element", "error_marker" }, { "mbtcp.trans_id", "transaction_id" },
        { "mbtcp.unit_id", "unit_id" }, { "modbus.func_code", "function" },
        { "modbus.exception", "exception" }, { "modbus.exception_code", "exception_code" },
        { "modbus.request_frame", "request_frame" }, { "modbus.reference_num", "register" },
        { "modbus.word_cnt", "quantity" }, { "modbus.regnum16", "register" },
        { "modbus.regnum32", "register" }, { "modbus.regval_uint16", "value" },
        { "modbus.regval_int16", "value" }, { "modbus.regval_uint32", "value" },
        { "modbus.regval_int32", "value" }, { "modbus.regval_float", "value" }, { "dnp3.src", "link_source" },
        { "dnp3.dst", "link_destination" }, { "dnp3.al.func", "function" }, { "dnp3.al.seq", "app_sequence" },
        { "dnp3.al.uns", "unsolicited" }, { "dnp3.al.con", "confirm_required" },
        { "dnp3.al.fir", "first_fragment" }, { "dnp3.al.fin", "final_fragment" },
        { "dnp3.al.iin", "indications" }, { "dnp3.al.obj", "object_group" },
        { "dnp3.al.index", "object_index" }, { "dnp3.al.ana.int", "value" }, { "dnp3.al.ana.float", "value" },
        { "dnp3.al.ana.double", "value" }, { "dnp3.al.timestamp", "protocol_time" } };
    return fields;
}
static void copyFields(Event& e, const QVector<DecodedField>& fields)
{
    for (const auto& f : fields) {
        const auto it = semanticFields().constFind(f.name);
        if (it != semanticFields().cend() && f.value.data.isValid())
            e.values[*it] = f.value;
    }
}
static void derived(Event& e, QString key, QVariant value, const QString& from)
{
    e.values[key] = { value, e.values.value(from).evidence };
}
QVector<Event> normalize(const DecodedPacket& packet)
{
    QVector<Event> events;
    Event base;
    base.frame = packet.frame;
    base.timeMs = packet.timeMs;
    base.malformed = packet.malformed;
    copyFields(base, packet.common);
    base.source = base.has("source_ip") ? base.text("source_ip") : base.text("source_mac");
    base.destination
        = base.has("destination_ip") ? base.text("destination_ip") : base.text("destination_mac");
    base.retransmission = base.flag("retransmission");
    base.reordered = base.flag("reordered");
    QString a = base.source + ":" + base.text("source_port"),
            b = base.destination + ":" + base.text("destination_port");
    base.flow
        = base.has("tcp_stream") ? "TCP:" + base.text("tcp_stream") : (a < b ? a + "|" + b : b + "|" + a);
    Event apci = base, mbap = base;
    auto append = [&](Event e) {
        e.ordinal = events.size();
        e.id = QString("%1:%2:%3").arg(e.protocol).arg(e.frame).arg(e.ordinal);
        events.push_back(std::move(e));
    };
    for (const auto& g : packet.groups) {
        Event e = base;
        copyFields(e, g.fields);
        if (g.protocol == "iec60870_104") {
            e.protocol = "IEC104";
            e.type = "APCI";
            apci = e;
            append(e);
        } else if (g.protocol == "iec60870_asdu") {
            e.protocol = "IEC104";
            if (apci.protocol != "IEC104" || apci.integer("apci_type") != 0)
                continue; // An IEC101 ASDU is not an IEC104 event.
            QVector<DecodedField> objects;
            for (const auto& f : g.fields)
                if (f.name == "iec60870_asdu.ioa")
                    objects.push_back(f);
            for (const auto& anchor : objects) {
                Event obj = base;
                obj.protocol = "IEC104";
                for (const auto& f : g.fields) {
                    const auto key = semanticFields().value(f.name);
                    if (key == "type_id" || key == "cot" || key == "common_address" || key == "negative"
                        || key == "test")
                        obj.values[key] = f.value;
                    if (f.parent == anchor.parent || f.ancestors.contains(anchor.parent))
                        obj.values[key] = f.value;
                }
                obj.values.remove("");
                obj.values["ioa"] = anchor.value;
                obj.object = "IOA:" + obj.text("ioa");
                const auto type = obj.integer("type_id");
                const bool command = (type >= 45 && type <= 51) || (type >= 58 && type <= 64);
                obj.type = command ? "CONTROL" : obj.has("value") ? "MEASUREMENT" : "ASDU";
                derived(obj, "control", command && obj.integer("cot") == 6, "type_id");
                if (command && obj.has("value") && !obj.has("command_value"))
                    obj.values["command_value"] = obj.values["value"];
                derived(obj, "measurement_kind", QString::number(type), "type_id");
                append(obj);
            }
            apci.protocol.clear();
        } else if (g.protocol == "goose") {
            e.protocol = "GOOSE";
            e.type = "PUBLISH";
            e.publisher = e.text("control_block");
            e.object = e.text("dataset");
            QByteArray numeric;
            QVector<Evidence> provenance;
            for (const auto& f : g.fields)
                if (semanticFields().value(f.name) == "dataset_value") {
                    numeric += f.name.toUtf8() + ":" + f.value.data.toString().toUtf8() + ";";
                    provenance += f.value.evidence;
                }
            if (!numeric.isEmpty())
                e.values["dataset_digest"]
                    = { QString::fromLatin1(
                            QCryptographicHash::hash(numeric, QCryptographicHash::Sha256).toHex()),
                          provenance };
            e.values.remove("dataset_value");
            append(e);
            int index = 0;
            for (const auto& f : g.fields)
                if (semanticFields().value(f.name) == "dataset_value") {
                    Event v = e;
                    v.type = "DATASET_VALUE";
                    v.object = e.object + ":" + QString::number(index++);
                    v.values["value"] = f.value;
                    derived(v, "measurement_kind", f.name, "value");
                    append(v);
                }
        } else if (g.protocol == "sv") {
            for (const auto& anchor : g.fields)
                if (anchor.name == "sv.svID") {
                    Event sample = base;
                    sample.protocol = "SV";
                    sample.type = "SAMPLE";
                    for (const auto& f : g.fields) {
                        const auto key = semanticFields().value(f.name);
                        if (key == "app_id" || f.parent == anchor.parent
                            || f.ancestors.contains(anchor.parent))
                            sample.values[key] = f.value;
                    }
                    sample.values.remove("");
                    sample.values.remove("value");
                    sample.values.remove("quality");
                    sample.publisher = sample.text("sv_id");
                    sample.object = sample.publisher;
                    append(sample);
                    int index = 0;
                    for (const auto& f : g.fields)
                        if (semanticFields().value(f.name) == "value"
                            && (f.parent == anchor.parent || f.ancestors.contains(anchor.parent))) {
                            Event v = sample;
                            v.type = "MEASUREMENT";
                            v.object = sample.object + ":" + QString::number(index++);
                            v.values["value"] = f.value;
                            derived(v, "measurement_kind", f.name, "value");
                            for (const auto& q : g.fields)
                                if (semanticFields().value(q.name) == "quality" && q.parent == f.parent)
                                    v.values["quality"] = q.value;
                            append(v);
                        }
                }
        } else if (g.protocol == "mbtcp") {
            mbap = e;
        } else if (g.protocol == "modbus") {
            e.protocol = "MODBUS";
            for (auto k : { "transaction_id", "unit_id" })
                if (mbap.has(k))
                    e.values[k] = mbap.values[k];
            e.type = (packet.modbusResponse || e.has("request_frame") || e.flag("exception")) ? "RESPONSE"
                : packet.modbusRequest                                                        ? "REQUEST"
                                                                                              : "UNRESOLVED";
            const auto function = e.integer("function");
            derived(e, "control",
                function == 5 || function == 6 || function == 15 || function == 16 || function == 22
                    || function == 23,
                "function");
            // A response is not an independently originated write command.
            derived(e, "write_operation", e.flag("control"), "function");
            derived(e, "control", e.flag("control") && e.type == "REQUEST", "function");
            e.object = "Register:" + e.text("register");
            append(e);
            for (const auto& f : g.fields)
                if (f.name == "modbus.regnum16" || f.name == "modbus.regnum32") {
                    Event r = e;
                    r.type = "REGISTER";
                    r.values["register"] = f.value;
                    r.object = "Register:" + f.value.data.toString();
                    r.values.remove("value");
                    for (const auto& v : g.fields)
                        if (v.parent == f.parent && semanticFields().value(v.name) == "value")
                            r.values["value"] = v.value;
                    derived(r, "control", false, "function");
                    if (r.has("value"))
                        append(r);
                }
        } else if (g.protocol == "mms") {
            bool found = false;
            for (const auto& marker : g.fields) {
                const auto key = semanticFields().value(marker.name);
                if (key != "request_marker" && key != "response_marker" && key != "error_marker")
                    continue;
                Event message = base;
                message.protocol = "MMS";
                message.type = key == "request_marker" ? "REQUEST"
                    : key == "response_marker"         ? "RESPONSE"
                                                       : "ERROR";
                const int node = marker.value.evidence.empty() ? -1 : marker.value.evidence.front().node;
                if (node < 0)
                    continue;
                for (const auto& f : g.fields)
                    if (f.parent == node || f.ancestors.contains(node))
                        message.values[semanticFields().value(f.name)] = f.value;
                derived(message, "control", message.type == "REQUEST" && message.integer("service") == 5,
                    "service");
                derived(message, "function", message.integer("service"), "service");
                message.object = "Service:" + message.text("service");
                append(message);
                found = true;
            }
            if (!found) {
                e.protocol = "MMS";
                e.type = "UNCONFIRMED";
                append(e);
            }
        } else if (g.protocol == "dnp3") {
            e.protocol = "DNP3";
            e.type = e.has("function") ? "APPLICATION" : "LINK";
            const auto f = e.integer("function");
            derived(e, "control", f >= 3 && f <= 6, "function");
            e.object = "Object:" + e.text("object_group") + ":" + e.text("object_index");
            append(e);
        }
    }
    return events;
}
}
