// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "Model.h"
namespace sspa
{
struct Sample {
    quint32 frame = 0;
    double timeMs = 0, value = 0;
};
struct Difference {
    quint32 previousFrame = 0, frame = 0;
    std::optional<double> delta, dtMs, ratePerSecond;
};
struct Statistics {
    int count = 0, invalidTimes = 0, duplicates = 0;
    std::optional<double> mean, median, variance, stddev, minimum, maximum, range, p05, p95, meanIntervalMs,
        jitterMs;
    QVector<Difference> differences;
    QVector<quint32> extremaFrames;
    bool numericOverflow = false;
};
Statistics calculate(const QVector<Sample>&, int maxDifferences = 500);
}
