// SPDX-License-Identifier: GPL-2.0-or-later
#include "core/Engine.h"
#include <cmath>
namespace sspa
{
class Sv final : public ProtocolAnalyzer
{
    QHash<QString, Event> last, logical, measurements;

public:
    void consume(const Event& e, Engine& engine) override
    {
        if (e.type == "MEASUREMENT" && e.has("quality")) {
            const auto key = measurementKey(e);
            if (measurements.contains(key) && measurements[key].has("quality")
                && measurements[key].values["quality"].data != e.values["quality"].data)
                engine.finding(e, "SV_MEASUREMENT_QUALITY_CHANGE", "PROTOCOL_STATUS",
                    measurements[key].text("quality"), e.text("quality"),
                    "Wireshark decoded a change in measurement quality. Interpret these flags using the "
                    "configured dataset/profile, not as an attack verdict.",
                    "Decoded SV measurement-quality comparison", { measurements[key].frame });
            measurements[key] = e;
            return;
        }
        if (e.type != "SAMPLE" || !e.has("sample_count"))
            return;
        if (e.text("sv_id").isEmpty() || e.source.isEmpty() || !e.has("app_id")) {
            engine.finding(e, "PUBLISHER_IDENTITY_UNRESOLVED", "CAPTURE_LIMITATION",
                "Decoded publisher identity", "Identity missing or outside extraction limits",
                "Publisher correlation was omitted because its required identity is unavailable.",
                "Conservative analyzer identity policy");
            return;
        }
        const QString identity = e.text("app_id") + ":" + e.text("sv_id") + ":" + e.destination;
        const QString key = identity + ":" + e.source;
        auto report = [&](QString rule, QString expected, QString observed, QString explanation,
                          quint32 prev) {
            engine.finding(e, rule, "STREAM_OBSERVATION", expected, observed, explanation,
                "IEC61850 sampled-value observations; counter wrap and rate depend on configured profile",
                { prev });
        };
        if (logical.contains(identity) && logical[identity].source != e.source)
            report("SV_PUBLISHER_CHANGE", "Configured stable stream publisher", "Source changed",
                "Another source supplied this logical sample stream. Check redundancy, topology and "
                "publisher configuration.",
                logical[identity].frame);
        logical[identity] = e;
        if (last.contains(key) && !e.reordered) {
            const auto& prev = last[key];
            const auto count = e.integer("sample_count"), old = prev.integer("sample_count");
            const auto next = engine.settings.svModulus > 0 ? (old + 1) % engine.settings.svModulus : old + 1;
            if (count != next)
                report(count == old ? "SV_DUPLICATE_SAMPLE_COUNTER" : "SV_SAMPLE_COUNTER_DISCONTINUITY",
                    QString::number(next), QString::number(count),
                    engine.settings.svModulus > 0
                        ? "The sample counter differs from the configured modulo progression. Missing "
                          "captured samples, duplicate capture, publisher reset or transport loss are "
                          "possible."
                        : "The counter does not advance by one. No profile modulus is configured, so a "
                          "decrease may be legitimate wraparound; its meaning remains unresolved.",
                    prev.frame);
            for (auto name : { "conf_rev", "sample_sync", "sample_rate", "vlan", "quality", "dataset" })
                if (e.has(name) && prev.has(name) && e.values[name].data != prev.values[name].data)
                    report(QString("SV_") + QString(name).toUpper() + "_CHANGE", "Stable stream attribute",
                        QString(name) + " changed",
                        "A sampled-value stream attribute changed. Validate engineering settings, "
                        "synchronization source and quality before security interpretation.",
                        prev.frame);
            const double dt = e.timeMs - prev.timeMs;
            if (engine.settings.intervalMs > 0 && dt >= 0
                && std::abs(dt - engine.settings.intervalMs) > engine.settings.intervalToleranceMs)
                engine.finding(e, "SV_INTERVAL_OUTSIDE_POLICY", "TIMING_ANOMALY",
                    QString::number(engine.settings.intervalMs), QString::number(dt),
                    "The observed interval differs from the configured sampling profile. Capture timestamp "
                    "precision, batching and packet loss affect this observation.",
                    "Configured sampling interval and tolerance", { prev.frame });
        }
        if (engine.settings.sampleRate > 0 && e.has("sample_rate")
            && e.integer("sample_rate") != engine.settings.sampleRate)
            engine.finding(e, "SV_SAMPLE_RATE_POLICY", "CONFIGURED_POLICY",
                QString::number(engine.settings.sampleRate), e.text("sample_rate"),
                "The decoded smpRate differs from configuration. Its units require the deployed "
                "smpMod/profile; no sample frequency is inferred here.",
                "Explicit expected_sample_rate policy");
        if (!e.reordered)
            last[key] = e;
        const int id = engine.begin(e, "Sampled-value observation");
        engine.complete(id, e, "OBSERVED");
    }
};
std::unique_ptr<ProtocolAnalyzer> makeSv()
{
    return std::make_unique<Sv>();
}
}
