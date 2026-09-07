// SPDX-License-Identifier: GPL-2.0-or-later
#include "Statistics.h"
#include <algorithm>
#include <cmath>
namespace sspa
{
Statistics calculate(const QVector<Sample>& samples, int maxDifferences)
{
    Statistics s;
    QVector<double> values, intervals;
    long double sum = 0;
    auto safe = [&](long double n) -> std::optional<double> {
        const double d = double(n);
        if (!std::isfinite(d)) {
            s.numericOverflow = true;
            return {};
        }
        return d;
    };
    for (const auto& p : samples)
        if (std::isfinite(p.value) && std::isfinite(p.timeMs)) {
            values.push_back(p.value);
            sum += p.value;
        }
    s.count = values.size();
    if (values.empty())
        return s;
    const long double mean = sum / values.size();
    s.mean = safe(mean);
    long double variance = 0;
    for (const auto v : values) {
        const long double d = static_cast<long double>(v) - mean;
        variance += d * d;
    }
    variance /= values.size();
    s.variance = safe(variance);
    s.stddev = safe(std::sqrt(variance));
    std::sort(values.begin(), values.end());
    s.minimum = values.front();
    s.maximum = values.back();
    s.range = safe(static_cast<long double>(values.back()) - values.front());
    auto quantile = [&](double p) {
        const double position = (values.size() - 1) * p;
        const auto lo = qsizetype(position), hi = std::min(lo + 1, values.size() - 1);
        return safe(static_cast<long double>(values[lo]) * (1 - (position - lo))
            + static_cast<long double>(values[hi]) * (position - lo));
    };
    s.median = quantile(.5);
    s.p05 = quantile(.05);
    s.p95 = quantile(.95);
    for (int i = 0; i < samples.size(); ++i) {
        if (samples[i].value == *s.minimum || samples[i].value == *s.maximum)
            if (s.extremaFrames.size() < 8)
                s.extremaFrames.push_back(samples[i].frame);
        if (i == 0)
            continue;
        const auto& a = samples[i - 1];
        const auto& b = samples[i];
        Difference d;
        d.previousFrame = a.frame;
        d.frame = b.frame;
        d.delta = safe(static_cast<long double>(b.value) - a.value);
        d.dtMs = safe(static_cast<long double>(b.timeMs) - a.timeMs);
        if (d.dtMs && *d.dtMs > 0) {
            intervals.push_back(*d.dtMs);
            if (d.delta)
                d.ratePerSecond = safe(static_cast<long double>(*d.delta) * 1000 / *d.dtMs);
        } else
            ++s.invalidTimes;
        if (d.delta && *d.delta == 0)
            ++s.duplicates;
        if (s.differences.size() < maxDifferences)
            s.differences.push_back(d);
    }
    if (!intervals.empty()) {
        long double meanDt = 0;
        for (auto d : intervals)
            meanDt += d;
        meanDt /= intervals.size();
        s.meanIntervalMs = safe(meanDt);
        long double square = 0;
        for (auto d : intervals) {
            const auto diff = d - meanDt;
            square += diff * diff;
        }
        s.jitterMs = safe(std::sqrt(square / intervals.size()));
    }
    return s;
}
}
