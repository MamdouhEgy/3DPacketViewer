// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/Model.h"
#include <QJsonObject>
#include <QSet>
namespace sspa
{
struct Asset {
    QString role, name;
    QSet<QString> peers, protocols, publishers, datasets;
    QSet<qint64> commonAddresses, ioas, vlans, functions;
    bool controlSource = false;
};
class Policy
{
public:
    QMap<QString, Asset> assets;
    double transactionTimeoutMs = 5000, expectedIntervalMs = 0, intervalToleranceMs = 0;
    qint64 svCounterModulus = 0, expectedSampleRate = 0;
    bool enforceControlSources = false;
    static std::optional<Policy> parse(const QJsonObject&, QString& error);
    QString role(const QString& endpoint) const;
    QVector<Finding> evaluate(const Event&) const;
};
}
