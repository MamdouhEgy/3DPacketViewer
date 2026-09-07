// SPDX-License-Identifier: GPL-2.0-or-later
#include "core/Engine.h"
namespace sspa
{
class Iec104 final : public ProtocolAnalyzer
{
    struct Link {
        QHash<QString, qint64> sent, ack;
        QString state = "UNKNOWN";
    };
    QHash<QString, Link> links;
    QHash<QString, int> pending;
    QHash<QString, Event> requests;

public:
    void consume(const Event& e, Engine& engine) override
    {
        auto& link = links[e.flow];
        if (e.type == "APCI") {
            if (e.has("tx") && !e.reordered) {
                const auto n = e.integer("tx");
                if (link.sent.contains(e.source)) {
                    const auto prev = link.sent[e.source];
                    if (n != ((prev + 1) % 32768))
                        engine.finding(e, "IEC104_TX_SEQUENCE_DISCONTINUITY", "SEQUENCE_OBSERVATION",
                            QString::number((prev + 1) % 32768), QString::number(n),
                            "The observed transmit sequence did not advance by one modulo 32768. Capture "
                            "loss, duplicate data, reconnection or delivery ordering must be checked before "
                            "treating this as a protocol fault.",
                            "IEC 60870-5-104 APCI 15-bit sequence behavior; continuous-stream observation "
                            "assumption");
                }
                link.sent[e.source] = n;
                if (link.state == "STOPPED")
                    engine.finding(e, "IEC104_DATA_AFTER_STOP", "STATE_OBSERVATION",
                        "Observed STARTDT confirmation before resumed data",
                        "I-format data while last confirmed state is STOPPED",
                        "Data followed an observed STOPDT confirmation without an observed STARTDT "
                        "confirmation. Missing control packets or capture discontinuity may explain this.",
                        "IEC 60870-5-104 data transfer control; observed-state model");
            }
            if (e.has("rx") && !e.reordered) {
                const auto rx = e.integer("rx");
                if (link.ack.contains(e.source) && ((rx - link.ack[e.source] + 32768) % 32768) > 16384)
                    engine.finding(e, "IEC104_ACK_REGRESSION", "SEQUENCE_OBSERVATION",
                        "Non-regressing acknowledgement within a continuous stream", QString::number(rx),
                        "Observed acknowledgement progression is inconsistent with the previous observation. "
                        "Reordering, restart and capture gaps remain possible.",
                        "IEC104 modulo-32768 acknowledgement; half-range comparison assumption");
                link.ack[e.source] = rx;
            }
            if (e.has("utype")) {
                const auto u = e.integer("utype");
                const bool activation = u == 1 || u == 4 || u == 16;
                const bool confirmation = u == 2 || u == 8 || u == 32;
                if (!activation && !confirmation) {
                    engine.finding(e, "IEC104_UNKNOWN_U_FUNCTION", "PROTOCOL_OBSERVATION",
                        "STARTDT, STOPDT or TESTFR function", QString::number(u),
                        "The decoded U-format function is not one of the modeled functions.",
                        "Pinned dissector u_types enumeration");
                    return;
                }
                const int base = activation ? u : u / 2;
                const QString name = base == 1 ? "STARTDT" : base == 4 ? "STOPDT" : "TESTFR";
                const QString key = e.flow + ":" + (activation ? e.source : e.destination) + ":" + name;
                if (activation) {
                    if (pending.contains(key))
                        engine.finding(e, "IEC104_DUPLICATE_" + name, "STATE_OBSERVATION",
                            "One outstanding activation", "Repeated activation before confirmation",
                            "A second activation was observed before its matching confirmation. Retries or "
                            "missing confirmations are possible.",
                            "Observed U-format request/confirmation pairing");
                    int id = engine.begin(e, name);
                    pending[key] = id;
                    engine.move(id, e, name + "_ACTIVATED", name + "_CONFIRMATION");
                    engine.deadline(id);
                } else {
                    const bool matched = pending.contains(key);
                    const int id = matched ? pending.take(key) : engine.begin(e, name, false);
                    engine.complete(id, e, name + "_CONFIRMED");
                    if (base == 1)
                        link.state = "STARTED";
                    if (base == 4)
                        link.state = "STOPPED";
                }
            }
            return;
        }
        if (e.type == "MEASUREMENT") {
            const int id = engine.begin(e, "Measurement observation");
            engine.complete(id, e, "OBSERVED");
            return;
        }
        if (!e.has("type_id") || !e.has("cot") || !e.has("ioa") || !e.has("common_address"))
            return;
        const auto type = e.integer("type_id"), cot = e.integer("cot");
        const bool command = (type >= 45 && type <= 51) || (type >= 58 && type <= 64);
        if (!command)
            return;
        const bool activation = cot == 6 || cot == 8;
        const QString key = e.flow + ":" + (activation ? e.source : e.destination) + ":"
            + QString::number(type) + ":" + e.text("common_address") + ":" + e.text("ioa") + ":"
            + e.text("select");
        if (activation) {
            if (pending.contains(key)) {
                const int old = pending.take(key);
                engine.transactions[old].completion = "UNRESOLVED";
                engine.finding(e, "IEC104_DUPLICATE_OPERATION", "TRANSACTION_OBSERVATION",
                    "An unambiguous outstanding operation",
                    "Another activation uses the same object and command type",
                    "Another matching activation appeared before completion. Application retry, capture loss "
                    "or duplicate operation are possible. The prior operation remains unresolved.",
                    "Analyzer correlation key: flow, initiator, type, Common Address, IOA and select/execute",
                    engine.transactions[old].frames);
            }
            const int id = engine.begin(e,
                cot == 8               ? "Control deactivation"
                    : e.flag("select") ? "Control selection"
                                       : "Control execution");
            pending[key] = id;
            requests[key] = e;
            engine.move(id, e, cot == 8 ? "DEACTIVATION_REQUESTED" : "COMMAND_ACTIVATED",
                cot == 8 ? "DEACTIVATION_CONFIRMATION" : "ACTIVATION_CONFIRMATION");
            engine.deadline(id);
            return;
        }
        if (cot != 7 && cot != 10 && cot != 8 && cot != 9 && !(cot >= 44 && cot <= 47)) {
            engine.finding(e, "IEC104_COMMAND_COT_UNMODELED", "PROTOCOL_OBSERVATION",
                "A supported command cause of transmission", QString::number(cot),
                "This command/cause combination is outside the modeled activation/deactivation/error "
                "sequence. Validate its TypeID-specific profile before concluding it is invalid.",
                "Modeled IEC104 control COT set; profile-dependent limitation");
            return;
        }
        const bool matched = pending.contains(key);
        const int id
            = matched ? pending[key] : engine.begin(e, "Control response without observed activation", false);
        if (id < 0)
            return;
        if (matched) {
            const auto& req = requests[key];
            if (req.has("command_value") && e.has("command_value")
                && req.values["command_value"].data != e.values["command_value"].data)
                engine.finding(e, "IEC104_COMMAND_PARAMETER_MISMATCH", "TRANSACTION_OBSERVATION",
                    req.text("command_value"), e.text("command_value"),
                    "The decoded command value differs between the correlated activation and response. "
                    "Inspect all contributing frames and verify correlation.",
                    "Echoed command-parameter comparison; not a cryptographic authenticity check",
                    { req.frame }, "WARNING");
        }
        if (e.flag("negative") || cot >= 44) {
            engine.transactions[id].negative = true;
            engine.complete(id, e, "NEGATIVE_RESPONSE");
            pending.remove(key);
            requests.remove(key);
        } else if (cot == 7) {
            engine.move(id, e, "COMMAND_CONFIRMED", "ACTIVATION_TERMINATION");
            if (e.flag("select")) {
                engine.complete(id, e, "SELECTION_CONFIRMED");
                pending.remove(key);
                requests.remove(key);
            } else {
                pending[key] = id;
                engine.deadline(id);
            }
        } else if (cot == 10) {
            const bool missingConfirmation = matched && engine.transactions[id].state != "COMMAND_CONFIRMED";
            if (missingConfirmation)
                engine.finding(e, "IEC104_TERMINATION_WITHOUT_CONFIRMATION", "TRANSACTION_OBSERVATION",
                    "Observed Activation Confirmation before Termination", engine.transactions[id].state,
                    "Termination was observed without a matching confirmation in the reconstructed "
                    "operation. A missing captured response is a possible explanation.",
                    "Modeled command activation/confirmation/termination sequence",
                    engine.transactions[id].frames);
            engine.complete(id, e, "COMMAND_TERMINATED");
            if (missingConfirmation)
                engine.transactions[id].completion = "INCOMPLETE_UNKNOWN";
            pending.remove(key);
            requests.remove(key);
        } else {
            engine.move(id, e, cot == 8 ? "DEACTIVATION_REQUESTED" : "DEACTIVATION_CONFIRMED");
            if (cot == 9) {
                engine.complete(id, e, "DEACTIVATED");
                pending.remove(key);
                requests.remove(key);
            }
        }
    }
};
std::unique_ptr<ProtocolAnalyzer> makeIec104()
{
    return std::make_unique<Iec104>();
}
}
