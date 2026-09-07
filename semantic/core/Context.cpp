// SPDX-License-Identifier: GPL-2.0-or-later
#include "Context.h"
#include <algorithm>
#include <cmath>
namespace sspa
{
Context buildContext(const Engine& engine, const Selector& query, const ContextLimits& limits)
{
    Context c;
    if (limits.maxEvents < 1 || limits.maxEvents > 5000 || limits.maxSeries < 1 || limits.maxSeries > 2000
        || limits.maxTransactions < 1 || limits.maxTransactions > 2000 || !std::isfinite(limits.maxWindowMs)
        || limits.maxWindowMs <= 0) {
        c.diagnostic = "Invalid semantic context limits";
        return c;
    }
    if ((query.startMs && !std::isfinite(*query.startMs)) || (query.endMs && !std::isfinite(*query.endMs))) {
        c.diagnostic = "Non-finite context timestamp";
        return c;
    }
    if (query.startMs && query.endMs
        && (*query.startMs > *query.endMs || *query.endMs - *query.startMs > limits.maxWindowMs)) {
        c.diagnostic = "Time window is reversed or exceeds the configured maximum";
        return c;
    }
    QVector<int> candidates;
    QSet<QString> transactionEvents;
    QSet<quint32> findingFrames;
    if (!query.transaction.isEmpty() || !query.transactionIds.empty())
        for (const auto& t : engine.transactions)
            if (t.id == query.transaction || query.transactionIds.contains(t.id))
                for (auto id : t.events)
                    transactionEvents.insert(id);
    if (!query.finding.isEmpty())
        for (const auto& f : engine.findings)
            if (f.id == query.finding)
                for (auto frame : f.frames)
                    findingFrames.insert(frame);
    if (!query.frames.empty()) {
        for (auto f : query.frames)
            candidates += engine.byFrame.value(f);
        std::sort(candidates.begin(), candidates.end());
    } else if (!query.flow.isEmpty())
        candidates = engine.byFlow.value(query.flow);
    else {
        candidates.reserve(engine.events.size());
        for (int i = 0; i < engine.events.size(); ++i)
            candidates.push_back(i);
    }
    QMap<QString, QVector<Sample>> samples;
    QMap<QString, Series> seriesInfo;
    QMap<QString, StateSeries> stateSeries;
    QVector<int> selected;
    QSet<QString> selectedIds;
    const QStringList numeric { "value", "command_value" };
    const QStringList symbolic { "st_num", "sq_num", "sample_count", "tx", "rx", "conf_rev", "quality",
        "sample_sync", "cot" };
    for (int position : candidates) {
        const auto& e = engine.events[position];
        if (!query.protocol.isEmpty() && e.protocol != query.protocol)
            continue;
        if (!query.publisher.isEmpty() && e.publisher != query.publisher)
            continue;
        if (!query.device.isEmpty() && e.source != query.device && e.destination != query.device)
            continue;
        if ((!query.transaction.isEmpty() || !query.transactionIds.empty())
            && !transactionEvents.contains(e.id))
            continue;
        if (!query.finding.isEmpty() && !findingFrames.contains(e.frame))
            continue;
        if (query.firstFrame && e.frame < query.firstFrame)
            continue;
        if (query.lastFrame && e.frame > query.lastFrame)
            continue;
        if (query.startMs && e.timeMs < *query.startMs)
            continue;
        if (query.endMs && e.timeMs > *query.endMs)
            continue;
        selected.push_back(position);
        selectedIds.insert(e.id);
        c.evidenceFrames.insert(e.frame);
        ++c.totalEvents;
        if (e.retransmission) {
            ++c.retransmissions;
            continue;
        }
        if (e.reordered)
            ++c.reordered;
        auto recordState = [&](const QString& name, double value) {
            const QString key = measurementKey(e) + ":" + name;
            if (!stateSeries.contains(key) && samples.size() + stateSeries.size() >= limits.maxSeries) {
                c.diagnostic = "Too many semantic series; narrow the context.";
                return false;
            }
            auto& state = stateSeries[key];
            if (!state.observations) {
                state.identity = key;
                state.protocol = e.protocol;
                state.object = e.object;
                state.feature = name;
                state.firstFrame = e.frame;
                state.firstValue = value;
            } else if (state.lastValue != value)
                ++state.changes;
            ++state.observations;
            state.lastFrame = e.frame;
            state.lastValue = value;
            return true;
        };
        for (const auto& name : symbolic)
            if (const auto value = e.number(name))
                if (!recordState(name, *value))
                    return c;
        for (const auto& name : numeric)
            if (const auto value = e.number(name)) {
                const auto& v = e.values[name];
                const bool code = v.data.metaType().id() == QMetaType::Bool
                    || std::any_of(v.evidence.begin(), v.evidence.end(), [](const Evidence& evidence) {
                           return evidence.field == "iec60870_asdu.diq.dpi"
                               || evidence.field == "iec60870_asdu.dco.on";
                       });
                if (code) {
                    if (!recordState(name, *value))
                        return c;
                    continue;
                }
                const QString key = measurementKey(e) + ":" + name;
                if (!samples.contains(key) && samples.size() + stateSeries.size() >= limits.maxSeries) {
                    c.diagnostic = "Context contains too many distinct series; narrow the selection or "
                                   "increase the series limit.";
                    return c;
                }
                samples[key].push_back({ e.frame, e.timeMs, *value });
                seriesInfo[key] = { key, e.protocol, e.object, name, {}, {} };
            }
    }
    for (const auto& state : stateSeries)
        c.states.push_back(state);
    c.summarized = selected.size() > limits.maxEvents;
    QSet<int> representatives;
    if (!selected.empty()) {
        const int count = std::min<int>(limits.maxEvents, selected.size());
        for (int i = 0; i < count; ++i)
            representatives.insert(
                selected[count == 1 ? 0 : qint64(i) * (selected.size() - 1) / (count - 1)]);
    }
    for (int i : selected)
        if (representatives.contains(i))
            c.events.push_back(engine.events[i]);
    for (auto it = samples.begin(); it != samples.end(); ++it) {
        auto series = seriesInfo[it.key()];
        series.statistics = calculate(it.value(), c.summarized ? 0 : limits.maxEvents);
        const auto& points = it.value();
        if (!points.empty()) {
            series.representatives.push_back(points.front());
            if (points.size() > 1)
                series.representatives.push_back(points.back());
            auto min = std::min_element(
                points.begin(), points.end(), [](auto a, auto b) { return a.value < b.value; });
            auto max = std::max_element(
                points.begin(), points.end(), [](auto a, auto b) { return a.value < b.value; });
            series.representatives.push_back(*min);
            series.representatives.push_back(*max);
            // Largest adjacent change is a deterministic representative, not an inferred attack/change point.
            if (points.size() > 1) {
                int largest = 1;
                long double delta = -1;
                for (int i = 1; i < points.size(); ++i) {
                    auto d = std::abs(static_cast<long double>(points[i].value) - points[i - 1].value);
                    if (d > delta) {
                        delta = d;
                        largest = i;
                    }
                }
                series.representatives.push_back(points[largest - 1]);
                series.representatives.push_back(points[largest]);
            }
        }
        c.series.push_back(series);
    }
    for (const auto& t : engine.transactions) {
        // A partial selection must not disclose the state/latency of unselected packets.
        bool relevant = !t.events.empty();
        for (const auto& id : t.events)
            relevant &= selectedIds.contains(id);
        if (relevant) {
            if (c.transactions.size() < limits.maxTransactions)
                c.transactions.push_back(t);
            else
                c.summarized = true;
        }
    }
    for (const auto& f : engine.findings) {
        bool relevant = !f.frames.empty();
        for (auto n : f.frames)
            relevant &= c.evidenceFrames.contains(n);
        if (relevant)
            c.findings.push_back(f);
    }
    if (c.summarized)
        c.diagnostic
            = "Context summarized: statistics use all selected events; event samples and transaction lists "
              "are bounded. Full adjacent-difference lists are omitted when event sampling is required.";
    return c;
}
Comparison compareContexts(Context a, Context b)
{
    Comparison result { std::move(a), std::move(b), {} };
    for (const auto& x : result.baseline.series)
        for (const auto& y : result.comparison.series)
            if (x.identity == y.identity) {
                auto delta = [](auto a, auto b) -> std::optional<double> {
                    if (!a || !b)
                        return {};
                    const double d = *b - *a;
                    return std::isfinite(d) ? std::optional<double>(d) : std::nullopt;
                };
                result.differences[x.identity]
                    = { { "mean_delta", delta(x.statistics.mean, y.statistics.mean) },
                          { "median_delta", delta(x.statistics.median, y.statistics.median) },
                          { "stddev_delta", delta(x.statistics.stddev, y.statistics.stddev) },
                          { "minimum_delta", delta(x.statistics.minimum, y.statistics.minimum) },
                          { "maximum_delta", delta(x.statistics.maximum, y.statistics.maximum) } };
            }
    return result;
}
}
