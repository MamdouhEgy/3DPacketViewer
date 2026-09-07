// SPDX-License-Identifier: GPL-2.0-or-later
#include "core/Engine.h"
namespace sspa
{
class Dnp3 final : public ProtocolAnalyzer
{
    QHash<QString, int> pending;
    QHash<QString, qint64> sequence;

public:
    void consume(const Event& e, Engine& engine) override
    {
        if (!e.has("function") || !e.has("app_sequence")) {
            const int id = engine.begin(e, "DNP3 link observation");
            engine.complete(id, e, "LINK_OBSERVED");
            return;
        }
        const auto function = e.integer("function"), seq = e.integer("app_sequence");
        const QString addresses = e.text("link_source") + ":" + e.text("link_destination");
        const QString stream = e.flow + ":" + e.source + ":" + addresses;
        const QString a = e.text("link_source"), b = e.text("link_destination");
        const QString circuit = e.flow + ":" + (a < b ? a + ":" + b : b + ":" + a);
        if (function == 130 || (function >= 128 && e.flag("unsolicited"))) {
            const int id = engine.begin(e, "DNP3 unsolicited response");
            engine.move(id, e, "UNSOLICITED_OBSERVED", e.flag("confirm_required") ? "CONFIRMATION" : "");
            if (e.flag("confirm_required")) {
                pending[circuit + ":" + e.source + ":" + QString::number(seq) + ":UNSOLICITED"] = id;
                engine.deadline(id);
            } else
                engine.complete(id, e, "UNSOLICITED_OBSERVED");
            return;
        }
        if (function == 0) {
            const auto key = circuit + ":" + e.destination + ":" + QString::number(seq) + ":UNSOLICITED";
            const int id = pending.contains(key)
                ? pending.take(key)
                : engine.begin(e, "DNP3 confirmation without observed response", false);
            engine.complete(id, e, "CONFIRMED");
            return;
        }
        const bool request = function < 128;
        const QString key = circuit + ":" + (request ? e.source : e.destination) + ":" + QString::number(seq);
        if (request) {
            if (sequence.contains(stream) && !e.reordered && e.flag("first_fragment")
                && seq != (sequence[stream] + 1) % 16)
                engine.finding(e, "DNP3_APPLICATION_SEQUENCE_OBSERVATION", "SEQUENCE_OBSERVATION",
                    QString::number((sequence[stream] + 1) % 16), QString::number(seq),
                    "Observed application request sequencing differs from simple modulo-16 progression. "
                    "Retries, multi-fragment exchange, startup and missing captures can explain it.",
                    "IEEE 1815 application sequence observation; simple-request profile");
            if (!e.reordered)
                sequence[stream] = seq;
            if (pending.contains(key)) {
                engine.transactions[pending.take(key)].completion = "UNRESOLVED";
                engine.finding(e, "DNP3_REQUEST_SEQUENCE_REUSE", "TRANSACTION_OBSERVATION",
                    "Unambiguous outstanding sequence", "Sequence reused",
                    "Outstanding requests share an application sequence; correlation remains unresolved.",
                    "DNP3 application request/response sequence key");
            }
            const int id = engine.begin(e, e.flag("control") ? "DNP3 control" : "DNP3 request");
            engine.move(id, e, "REQUESTED", "RESPONSE");
            if (function == 6)
                engine.complete(id, e, "DIRECT_OPERATE_NO_ACK_SENT");
            else {
                pending[key] = id;
                engine.deadline(id);
            }
        } else {
            const bool matched = pending.contains(key);
            const int id = matched ? pending.take(key)
                                   : engine.begin(e, "DNP3 response without observed request", false);
            if (e.flag("final_fragment"))
                engine.complete(id, e, "RESPONDED");
            else {
                engine.move(id, e, "RESPONSE_FRAGMENT", "FINAL_FRAGMENT");
                const QString next = circuit + ":" + e.destination + ":" + QString::number((seq + 1) % 16);
                pending[next] = id;
                engine.deadline(id);
            }
            if (e.has("indications") && e.integer("indications") != 0)
                engine.finding(e, "DNP3_INTERNAL_INDICATIONS", "PROTOCOL_STATUS",
                    "Review internal indication flags", e.text("indications"),
                    "The outstation reports internal indication flags. These may describe restart, class "
                    "data, device trouble or request errors and are not uniformly faults.",
                    "Wireshark dnp3.al.iin decoded bitfield");
        }
    }
};
std::unique_ptr<ProtocolAnalyzer> makeDnp3()
{
    return std::make_unique<Dnp3>();
}
}
