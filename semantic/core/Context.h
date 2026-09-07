// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "Engine.h"
#include "Statistics.h"
#include <QSet>
namespace sspa
{
struct Selector {
    QSet<quint32> frames;
    QSet<QString> transactionIds;
    QString protocol, flow, publisher, device, transaction, finding;
    std::optional<double> startMs, endMs;
    quint32 firstFrame = 0, lastFrame = 0;
};
struct ContextLimits {
    int maxEvents = 500, maxSeries = 256, maxTransactions = 200;
    double maxWindowMs = 3600000;
};
struct Series {
    QString identity, protocol, object, feature;
    Statistics statistics;
    QVector<Sample> representatives;
};
struct Context {
    QString type = "SEMANTIC_CONTEXT", diagnostic;
    int totalEvents = 0, retransmissions = 0, reordered = 0;
    bool summarized = false;
    QVector<Event> events;
    QVector<Series> series;
    QVector<Transaction> transactions;
    QVector<Finding> findings;
    QSet<quint32> evidenceFrames;
};
Context buildContext(const Engine&, const Selector&, const ContextLimits& = {});
struct Comparison {
    Context baseline, comparison;
    QMap<QString, QMap<QString, std::optional<double>>> differences;
};
Comparison compareContexts(Context, Context);
}
