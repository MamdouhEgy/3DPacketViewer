// SPDX-License-Identifier: GPL-2.0-or-later
#include "core/Engine.h"
namespace sspa
{
class Mms final : public ProtocolAnalyzer
{
    QHash<QString, int> pending;
    QHash<QString, Event> requests;

public:
    void consume(const Event& e, Engine& engine) override
    {
        if (!e.has("invoke_id")) {
            const int id = engine.begin(e, "MMS unconfirmed observation");
            engine.complete(id, e, "OBSERVED");
            return;
        }
        const bool request = e.type == "REQUEST";
        const QString key = e.flow + ":" + (request ? e.source : e.destination) + ":" + e.text("invoke_id");
        if (request) {
            if (pending.contains(key)) {
                engine.transactions[pending.take(key)].completion = "UNRESOLVED";
                engine.finding(e, "MMS_INVOKE_ID_REUSE", "TRANSACTION_OBSERVATION",
                    "Unique outstanding invoke ID", "Invoke ID reused",
                    "An invoke ID was reused before the matching response was observed. Pairing is "
                    "ambiguous; capture gaps and retries are possible.",
                    "ISO 9506 confirmed-service invoke-ID association");
            }
            const int id = engine.begin(e,
                e.integer("service") == 5       ? "MMS write"
                    : e.integer("service") == 4 ? "MMS read"
                                                : "MMS confirmed service");
            pending[key] = id;
            requests[key] = e;
            engine.move(id, e, "REQUESTED", "RESPONSE");
            engine.deadline(id);
        } else if (e.type == "RESPONSE" || e.type == "ERROR") {
            const bool matched = pending.contains(key);
            const int id = matched ? pending.take(key)
                                   : engine.begin(e, "MMS response without observed request", false);
            if (matched) {
                const auto req = requests.take(key);
                if (req.has("service") && e.has("service") && req.integer("service") != e.integer("service"))
                    engine.finding(e, "MMS_SERVICE_MISMATCH", "TRANSACTION_OBSERVATION", req.text("service"),
                        e.text("service"),
                        "The correlated confirmed-service response does not match the request service. Check "
                        "association identity and capture boundaries.",
                        "ISO 9506 confirmed-service association", { req.frame }, "WARNING");
            }
            if (e.type == "ERROR") {
                engine.transactions[id].negative = true;
                engine.finding(e, "MMS_CONFIRMED_ERROR", "PROTOCOL_RESPONSE", "Successful service result",
                    "Confirmed error",
                    "MMS returned a protocol-defined service error. Inspect the service and device "
                    "diagnostics; this is not an attack verdict.",
                    "ISO 9506 Confirmed-ErrorPDU");
            }
            engine.complete(id, e, e.type == "ERROR" ? "SERVICE_ERROR" : "RESPONDED");
        }
    }
};
std::unique_ptr<ProtocolAnalyzer> makeMms()
{
    return std::make_unique<Mms>();
}
}
