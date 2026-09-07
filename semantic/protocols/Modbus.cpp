// SPDX-License-Identifier: GPL-2.0-or-later
#include "core/Engine.h"
namespace sspa
{
class Modbus final : public ProtocolAnalyzer
{
    QHash<QString, int> pending;
    QHash<QString, Event> requests, registers;

public:
    void consume(const Event& e, Engine& engine) override
    {
        if (e.type == "REGISTER") {
            const auto key = measurementKey(e);
            if (registers.contains(key) && e.has("value")
                && registers[key].values["value"].data != e.values["value"].data)
                engine.finding(e, "MODBUS_REGISTER_CHANGE", "VALUE_OBSERVATION", registers[key].text("value"),
                    e.text("value"),
                    "The decoded register value changed between observations. Register scaling and "
                    "engineering meaning require the deployed asset map; a change is not intrinsically "
                    "malicious.",
                    "Wireshark decoded register number/value comparison", { registers[key].frame });
            registers[key] = e;
            return;
        }
        if (!e.has("transaction_id") || !e.has("unit_id") || !e.has("function"))
            return;
        if (e.type != "REQUEST" && e.type != "RESPONSE") {
            const int id = engine.begin(e, "Modbus direction unresolved", false);
            engine.move(id, e, "UNRESOLVED");
            engine.transactions[id].completion = "UNRESOLVED";
            return;
        }
        const bool request = e.type == "REQUEST";
        const QString key = e.flow + ":" + (request ? e.source : e.destination) + ":"
            + e.text("transaction_id") + ":" + e.text("unit_id");
        if (request) {
            if (pending.contains(key)) {
                const int old = pending.take(key);
                engine.transactions[old].completion = "UNRESOLVED";
                engine.finding(e, "MODBUS_TRANSACTION_ID_REUSE", "TRANSACTION_OBSERVATION",
                    "Unique outstanding transaction identifier",
                    "Transaction ID reused before observed response",
                    "Two requests share an outstanding transaction identifier. Retry, capture loss or "
                    "identifier reuse makes pairing ambiguous.",
                    "Modbus Messaging on TCP/IP Implementation Guide, MBAP transaction identifier",
                    engine.transactions[old].frames);
            }
            const int id = engine.begin(e, e.flag("control") ? "Modbus write" : "Modbus request");
            pending[key] = id;
            requests[key] = e;
            engine.move(id, e, "REQUESTED", "RESPONSE");
            engine.deadline(id);
        } else {
            const bool matched = pending.contains(key);
            const int id = matched ? pending.take(key)
                                   : engine.begin(e, "Modbus response without observed request", false);
            if (matched) {
                const auto req = requests.take(key);
                if (req.integer("function") != e.integer("function"))
                    engine.finding(e, "MODBUS_FUNCTION_MISMATCH", "TRANSACTION_OBSERVATION",
                        req.text("function"), e.text("function"),
                        "The response function differs from the correlated request function. Check "
                        "transaction reuse and capture completeness.",
                        "Modbus request/response function correlation", { req.frame }, "WARNING");
                if (e.flag("write_operation") && req.has("register") && e.has("register")
                    && req.integer("register") != e.integer("register"))
                    engine.finding(e, "MODBUS_WRITE_ADDRESS_MISMATCH", "TRANSACTION_OBSERVATION",
                        req.text("register"), e.text("register"),
                        "The echoed write address differs from the request.",
                        "Modbus write-response address comparison", { req.frame }, "WARNING");
            }
            if (e.flag("exception")) {
                engine.finding(e, "MODBUS_EXCEPTION_RESPONSE", "PROTOCOL_RESPONSE", "Normal response",
                    "Exception code " + e.text("exception_code"),
                    "The server returned a Modbus exception. This is a protocol-defined failure response, "
                    "not itself a protocol violation or attack.",
                    "Modbus Application Protocol exception responses");
                engine.transactions[id].negative = true;
            }
            engine.complete(id, e, e.flag("exception") ? "EXCEPTION" : "RESPONDED");
        }
    }
};
std::unique_ptr<ProtocolAnalyzer> makeModbus()
{
    return std::make_unique<Modbus>();
}
}
