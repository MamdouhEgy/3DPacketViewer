// SPDX-License-Identifier: GPL-2.0-or-later
#include "Sanitizer.h"
#include "extraction/Normalizer.h"
#include <QJsonArray>
#include <QRegularExpression>
#include <cmath>
namespace sspa
{
static QJsonValue number(std::optional<double> v)
{
    return v && std::isfinite(*v) ? QJsonValue(*v) : QJsonValue(QJsonValue::Null);
}
static QJsonArray frames(const QVector<quint32>& values)
{
    QJsonArray a;
    for (auto n : values)
        a.append(qint64(n));
    return a;
}
static QJsonObject stats(const Statistics& s)
{
    QJsonArray differences, extrema;
    for (const auto& d : s.differences)
        differences.append(QJsonObject { { "previous_frame", qint64(d.previousFrame) },
            { "frame", qint64(d.frame) }, { "delta", number(d.delta) }, { "delta_time_ms", number(d.dtMs) },
            { "rate_per_second", number(d.ratePerSecond) } });
    for (auto f : s.extremaFrames)
        extrema.append(qint64(f));
    return { { "count", s.count }, { "mean", number(s.mean) }, { "median", number(s.median) },
        { "population_variance", number(s.variance) }, { "population_stddev", number(s.stddev) },
        { "minimum", number(s.minimum) }, { "maximum", number(s.maximum) }, { "range", number(s.range) },
        { "p05", number(s.p05) }, { "p95", number(s.p95) }, { "mean_interval_ms", number(s.meanIntervalMs) },
        { "interval_stddev_ms", number(s.jitterMs) }, { "nonpositive_time_differences", s.invalidTimes },
        { "unchanged_adjacent_values", s.duplicates }, { "numeric_overflow", s.numericOverflow },
        { "adjacent_differences", differences }, { "extrema_frames", extrema } };
}
static QJsonArray evidence(const QVector<Evidence>& values, bool sanitized)
{
    QJsonArray a;
    for (const auto& r : values) {
        if (sanitized && !semanticFields().contains(r.field))
            continue;
        QJsonObject o { { "frame", qint64(r.frame) }, { "field", r.field }, { "generated", r.generated } };
        if (!sanitized) {
            o["node"] = r.node;
            o["source"] = r.source;
            o["source_name"] = r.sourceName;
            o["current_frame_source"] = r.currentFrameSource;
            o["byte_offset"] = r.offset;
            o["byte_length"] = r.length;
        }
        a.append(o);
    }
    return a;
}
QJsonObject localEvent(const Event& e)
{
    QJsonObject values;
    for (auto it = e.values.begin(); it != e.values.end(); ++it)
        values[it.key()] = QJsonObject { { "value", QJsonValue::fromVariant(it->data) },
            { "provenance", evidence(it->evidence, false) } };
    return { { "schema_version", SchemaVersion }, { "id", e.id }, { "protocol", e.protocol },
        { "event_type", e.type }, { "frame", qint64(e.frame) }, { "relative_time_ms", e.timeMs },
        { "source", e.source }, { "destination", e.destination }, { "source_role", e.sourceRole },
        { "destination_role", e.destinationRole }, { "flow", e.flow }, { "publisher", e.publisher },
        { "object", e.object }, { "retransmission", e.retransmission }, { "reordered", e.reordered },
        { "malformed", e.malformed }, { "values", values } };
}
QJsonObject localTransaction(const Transaction& t)
{
    QJsonArray transitions;
    for (const auto& s : t.transitions)
        transitions.append(
            QJsonObject { { "previous", s.previous }, { "current", s.current }, { "trigger", s.trigger },
                { "expected", s.expected }, { "frame", qint64(s.frame) }, { "relative_time_ms", s.timeMs } });
    return { { "id", t.id }, { "protocol", t.protocol }, { "source", t.source },
        { "destination", t.destination }, { "source_role", t.sourceRole },
        { "destination_role", t.destinationRole }, { "operation", t.operation }, { "object", t.object },
        { "frames", frames(t.frames) }, { "start_ms", t.startMs }, { "end_ms", t.endMs },
        { "latency_ms",
            t.endMs >= t.startMs ? QJsonValue(t.endMs - t.startMs) : QJsonValue(QJsonValue::Null) },
        { "state", t.state }, { "completion", t.completion }, { "negative_response", t.negative },
        { "transitions", transitions } };
}
QJsonObject localFinding(const Finding& f)
{
    return { { "id", f.id }, { "rule", f.rule }, { "protocol", f.protocol },
        { "classification", "DETERMINISTIC_FINDING" }, { "category", f.category }, { "severity", f.severity },
        { "frames", frames(f.frames) }, { "expected", f.expected }, { "observed", f.observed },
        { "explanation", f.explanation }, { "basis", f.basis },
        { "provenance", evidence(f.evidence, false) } };
}
QJsonObject localReport(const Engine& engine, bool boundary)
{
    QJsonArray events, transactions, findings;
    for (const auto& e : engine.events)
        events.append(localEvent(e));
    for (const auto& t : engine.snapshotTransactions(boundary))
        transactions.append(localTransaction(t));
    for (const auto& f : engine.findings)
        findings.append(localFinding(f));
    return { { "schema_version", SchemaVersion }, { "analyzer_version", AnalyzerVersion },
        { "events", events }, { "transactions", transactions }, { "findings", findings },
        { "diagnostic", engine.diagnostic }, { "ai_included", false } };
}
QString Sanitizer::token(const QString& kind, const QString& original)
{
    const QString key = kind + ":" + original;
    if (!identities.contains(key))
        identities[key] = kind + "_" + QString::number(identities.size() + 1);
    return identities[key];
}
QJsonObject Sanitizer::encode(const Context& c)
{
    QJsonArray events, series, states, transactions, findings, ranges;
    const QSet<QString> protocols { "IEC104", "GOOSE", "SV", "MMS", "MODBUS", "DNP3" };
    const QSet<QString> types { "APCI", "CONTROL", "MEASUREMENT", "ASDU", "PUBLISH", "DATASET_VALUE",
        "SAMPLE", "REGISTER", "REQUEST", "RESPONSE", "UNRESOLVED", "ERROR", "UNCONFIRMED", "APPLICATION",
        "LINK" };
    const QSet<QString> roles { "UNKNOWN", "CONTROL_CENTER", "RTU", "PROTECTION_IED", "MERGING_UNIT", "HMI",
        "ENGINEERING", "GATEWAY" };
    const QSet<QString> allowed { "type_id", "cot", "common_address", "ioa", "negative", "test", "value",
        "command_value", "select", "quality", "qualifier", "apci_type", "utype", "tx", "rx", "app_id",
        "conf_rev", "st_num", "sq_num", "ttl_ms", "simulation", "needs_commissioning", "sample_count",
        "sample_sync", "sample_rate", "sample_mode", "invoke_id", "service", "transaction_id", "unit_id",
        "function", "exception", "exception_code", "request_frame", "register", "quantity", "app_sequence",
        "unsolicited", "confirm_required", "first_fragment", "final_fragment", "indications", "object_group",
        "object_index", "control", "write_operation", "vlan", "vlan_priority" };
    for (const auto& e : c.events) {
        if (!protocols.contains(e.protocol) || !types.contains(e.type))
            continue;
        QJsonObject fields, provenance;
        for (const auto& key : allowed)
            if (const auto value = e.number(key)) {
                fields[key] = e.values[key].data.metaType().id() == QMetaType::Bool
                    ? QJsonValue(e.values[key].data.toBool())
                    : QJsonValue(*value);
                provenance[key] = evidence(e.values[key].evidence, true);
            }
        for (const auto& key : { "dataset", "control_block", "sv_id", "go_id", "dataset_digest" })
            if (e.has(key))
                fields[key] = token(key, e.text(key));
        events.append(QJsonObject { { "event_id", token("event", e.id) }, { "protocol", e.protocol },
            { "event_type", e.type }, { "frame", qint64(e.frame) }, { "relative_time_ms", e.timeMs },
            { "source", token("endpoint", e.source) }, { "destination", token("endpoint", e.destination) },
            { "source_role", roles.contains(e.sourceRole) ? e.sourceRole : "UNKNOWN" },
            { "destination_role", roles.contains(e.destinationRole) ? e.destinationRole : "UNKNOWN" },
            { "stream", token("stream", e.flow + ":" + e.publisher) },
            { "object", token("object", e.object) }, { "fields", fields }, { "provenance", provenance },
            { "retransmission", e.retransmission }, { "reordered", e.reordered } });
    }
    for (const auto& s : c.series) {
        if (!protocols.contains(s.protocol) || !allowed.contains(s.feature))
            continue;
        QJsonArray points;
        for (const auto& p : s.representatives)
            points.append(QJsonObject {
                { "frame", qint64(p.frame) }, { "relative_time_ms", p.timeMs }, { "value", p.value } });
        series.append(QJsonObject { { "series_id", token("series", s.identity) }, { "protocol", s.protocol },
            { "object", token("object", s.object) }, { "feature", s.feature },
            { "statistics", stats(s.statistics) }, { "representative_observations", points } });
    }
    for (const auto& s : c.states) {
        if (!protocols.contains(s.protocol) || !allowed.contains(s.feature))
            continue;
        states.append(QJsonObject { { "series_id", token("series", s.identity) }, { "protocol", s.protocol },
            { "object", token("object", s.object) }, { "feature", s.feature },
            { "observation_count", s.observations }, { "observed_change_count", s.changes },
            { "first_frame", qint64(s.firstFrame) }, { "last_frame", qint64(s.lastFrame) },
            { "first_code", s.firstValue }, { "last_code", s.lastValue },
            { "interpretation",
                "Decoded codes/counters: changes are observations; protocol modules establish sequencing. No "
                "mean or physical magnitude is implied." } });
    }
    const QRegularExpression safeId("^[A-Z0-9_:-]{1,200}$");
    for (const auto& f : c.findings) {
        if (!protocols.contains(f.protocol) || !safeId.match(f.rule).hasMatch())
            continue;
        QVector<quint32> relevant;
        for (auto frame : f.frames)
            if (c.evidenceFrames.contains(frame))
                relevant.push_back(frame);
        // No free-form expected/observed/explanation text crosses this boundary.
        findings.append(QJsonObject { { "finding_id", f.rule }, { "occurrence_id", token("finding", f.id) },
            { "protocol", f.protocol },
            { "category", safeId.match(f.category).hasMatch() ? f.category : "OBSERVATION" },
            { "severity", f.severity == "WARNING" ? "WARNING" : "NOTICE" }, { "frames", frames(relevant) } });
    }
    for (const auto& t : c.transactions) {
        if (!protocols.contains(t.protocol))
            continue;
        QVector<quint32> relevant;
        for (auto frame : t.frames)
            if (c.evidenceFrames.contains(frame))
                relevant.push_back(frame);
        transactions.append(QJsonObject { { "transaction_id", token("transaction", t.id) },
            { "protocol", t.protocol }, { "frames", frames(relevant) },
            { "state", safeId.match(t.state).hasMatch() ? t.state : "UNRESOLVED" },
            { "completion", safeId.match(t.completion).hasMatch() ? t.completion : "UNRESOLVED" },
            { "latency_ms",
                t.endMs >= t.startMs ? QJsonValue(t.endMs - t.startMs) : QJsonValue(QJsonValue::Null) } });
    }
    auto sorted = c.evidenceFrames.values();
    std::sort(sorted.begin(), sorted.end());
    for (int i = 0; i < sorted.size();) {
        quint32 first = sorted[i], last = first;
        while (++i < sorted.size() && sorted[i] == last + 1)
            last = sorted[i];
        ranges.append(QJsonArray { qint64(first), qint64(last) });
    }
    return { { "schema_version", SchemaVersion }, { "context_type", "SEMANTIC_CONTEXT" },
        { "analyzer_version", AnalyzerVersion }, { "preprocessing_version", "1.0" },
        { "event_count", c.totalEvents }, { "retransmissions", c.retransmissions },
        { "reordered_events", c.reordered }, { "summarized", c.summarized },
        { "summary_policy",
            c.summarized ? "All-event statistics; bounded representative events, extrema and largest "
                           "adjacent changes; bounded transactions"
                         : "Full selected semantic events" },
        { "evidence_frame_ranges", ranges }, { "events", events }, { "series", series },
        { "state_series", states }, { "transactions", transactions },
        { "deterministic_findings", findings } };
}
SanitizedContext Sanitizer::build(const Context& c)
{
    SanitizedContext result;
    result.evidenceFrames = c.evidenceFrames;
    if (c.totalEvents == 0 || (!c.diagnostic.isEmpty() && !c.summarized)) {
        result.error = c.diagnostic.isEmpty() ? "No semantic events selected" : c.diagnostic;
        return result;
    }
    result.json = encode(c);
    for (const auto& f : c.findings)
        result.findingIds.insert(f.rule);
    return result;
}
SanitizedContext Sanitizer::build(const Comparison& c)
{
    auto a = build(c.baseline), b = build(c.comparison);
    if (!a.error.isEmpty())
        return a;
    if (!b.error.isEmpty())
        return b;
    QJsonArray differences;
    for (auto it = c.differences.begin(); it != c.differences.end(); ++it) {
        QJsonObject d { { "series_id", token("series", it.key()) } };
        for (auto k = it->begin(); k != it->end(); ++k)
            d[k.key()] = number(k.value());
        differences.append(d);
    }
    SanitizedContext result;
    result.evidenceFrames = a.evidenceFrames | b.evidenceFrames;
    result.findingIds = a.findingIds | b.findingIds;
    result.json = { { "schema_version", SchemaVersion }, { "context_type", "SEMANTIC_RANGE_COMPARISON" },
        { "baseline", a.json }, { "comparison", b.json }, { "computed_differences", differences },
        { "alignment",
            "Differences require the same local stream/object identity; other streams remain separate "
            "summaries" } };
    return result;
}
}
