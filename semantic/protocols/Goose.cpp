// SPDX-License-Identifier: GPL-2.0-or-later
#include "core/Engine.h"
namespace sspa
{
class Goose final : public ProtocolAnalyzer
{
    QHash<QString, Event> last, logical;

public:
    void consume(const Event& e, Engine& engine) override
    {
        if (e.type != "PUBLISH" || !e.has("st_num") || !e.has("sq_num"))
            return;
        if (e.text("control_block").isEmpty() || e.source.isEmpty() || !e.has("app_id")) {
            engine.finding(e, "PUBLISHER_IDENTITY_UNRESOLVED", "CAPTURE_LIMITATION",
                "Decoded publisher identity", "Identity missing or outside extraction limits",
                "Publisher correlation was omitted because its required identity is unavailable.",
                "Conservative analyzer identity policy");
            return;
        }
        // confRev/dataset/MAC are attributes, not key components: changes must stay observable.
        const QString logicalKey = e.text("app_id") + ":" + e.text("control_block") + ":" + e.destination;
        const QString key = logicalKey + ":" + e.source;
        auto report = [&](QString rule, QString expected, QString observed, QString why, quint32 prev) {
            engine.finding(e, rule, "PUBLISHER_OBSERVATION", expected, observed, why,
                "IEC 61850-8-1 GOOSE state/retransmission semantics; observed continuous-publisher "
                "assumption",
                { prev });
        };
        if (logical.contains(logicalKey) && logical[logicalKey].source != e.source)
            report("GOOSE_PUBLISHER_IDENTITY_CHANGE", "Stable source for a logical publisher",
                "Source identity changed",
                "The same logical GOOSE identity was observed from another source. Redundant equipment, "
                "reconfiguration, duplicate publisher or spoofed traffic are possible; verify topology.",
                logical[logicalKey].frame);
        logical[logicalKey] = e;
        if (last.contains(key)) {
            const auto& prev = last[key];
            const auto st = e.integer("st_num"), sq = e.integer("sq_num");
            if (!e.reordered) {
                const bool wrap = prev.integer("st_num") == 4294967295LL && st == 1;
                if (st < prev.integer("st_num") && !wrap)
                    report("GOOSE_STNUM_REGRESSION", "No decrease during continuous operation absent reset",
                        QString("%1 -> %2").arg(prev.integer("st_num")).arg(st),
                        "The observed GOOSE state number decreased. Possible causes include publisher "
                        "restart, duplicate publisher, replayed traffic, capture discontinuity, or another "
                        "state-reset condition.",
                        prev.frame);
                if (st == prev.integer("st_num") && sq <= prev.integer("sq_num"))
                    report("GOOSE_SQNUM_NONINCREASING",
                        "Increasing retransmission sequence for unchanged state", QString::number(sq),
                        "Retransmission sequence did not increase. Duplicate capture, replay-like traffic, "
                        "restart or counter wrap must be investigated; this is not an attack verdict.",
                        prev.frame);
                if (st != prev.integer("st_num") && sq != 0)
                    report("GOOSE_NEW_STATE_FIRST_OBSERVATION",
                        "sqNum zero at the first transmission of a new state", QString::number(sq),
                        "The first observed transmission of this state has nonzero sqNum. Earlier "
                        "transmissions may be absent from the capture.",
                        prev.frame);
            }
            for (auto name : { "conf_rev", "dataset", "go_id", "vlan", "vlan_priority", "simulation",
                     "needs_commissioning", "dataset_digest", "quality" }) {
                if (e.has(name) && prev.has(name) && e.values[name].data != prev.values[name].data) {
                    if (QString(name) == "dataset_digest" && st != prev.integer("st_num"))
                        continue;
                    report(QString("GOOSE_") + QString(name).toUpper() + "_CHANGE",
                        "Stable attribute absent an expected configuration/state change",
                        QString(name) + " changed",
                        "A publisher attribute changed. Verify the configured dataset, engineering revision, "
                        "quality and commissioning state; legitimate operational changes are possible.",
                        prev.frame);
                }
            }
            const double dt = e.timeMs - prev.timeMs;
            if (dt >= 0 && prev.has("ttl_ms") && dt > prev.number("ttl_ms").value_or(0))
                report("GOOSE_TIME_ALLOWED_TO_LIVE_EXCEEDED",
                    "Next observed message before prior timeAllowedtoLive", QString("%1 ms").arg(dt),
                    "The observed interarrival interval exceeds the preceding timeAllowedtoLive. Capture "
                    "loss and missing paths can resemble a publisher timeout.",
                    prev.frame);
            if (engine.settings.intervalMs > 0 && dt >= 0
                && std::abs(dt - engine.settings.intervalMs) > engine.settings.intervalToleranceMs)
                engine.finding(e, "GOOSE_CONFIGURED_INTERVAL", "TIMING_ANOMALY",
                    QString::number(engine.settings.intervalMs), QString::number(dt),
                    "Interarrival time differs from the explicitly configured expectation; GOOSE "
                    "retransmission schedules normally vary after state changes.",
                    "Configured expected_interval_ms and interval_tolerance_ms", { prev.frame });
        }
        if (!e.reordered)
            last[key] = e;
        const int id = engine.begin(e, "GOOSE publication");
        engine.complete(id, e, "OBSERVED");
    }
};
std::unique_ptr<ProtocolAnalyzer> makeGoose()
{
    return std::make_unique<Goose>();
}
}
