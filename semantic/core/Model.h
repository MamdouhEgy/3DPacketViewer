// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QMap>
#include <QString>
#include <QVariant>
#include <QVector>
#include <optional>
namespace sspa
{
inline constexpr auto SchemaVersion = "1.0";
inline constexpr auto AnalyzerVersion = "0.1.0";
struct Evidence {
    quint32 frame = 0;
    QString field;
    int node = -1, source = -1;
    qint64 offset = -1, length = 0;
    bool generated = false;
    QString sourceName = {};
    bool currentFrameSource = false;
};
struct Value {
    QVariant data;
    QVector<Evidence> evidence;
};
struct Event {
    QString id, protocol, type, flow, publisher, object;
    QString source, destination, sourceRole = "UNKNOWN", destinationRole = "UNKNOWN";
    quint32 frame = 0;
    int ordinal = 0;
    double timeMs = 0;
    bool retransmission = false, reordered = false, malformed = false;
    QMap<QString, Value> values;
    bool has(const QString& key) const
    {
        return values.contains(key);
    }
    std::optional<double> number(const QString& key) const;
    qint64 integer(const QString& key, qint64 fallback = -1) const;
    QString text(const QString& key) const;
    bool flag(const QString& key) const
    {
        return integer(key, 0) != 0;
    }
};
struct Transition {
    QString previous, current, trigger, expected;
    quint32 frame = 0;
    double timeMs = 0;
};
struct Transaction {
    QString id, protocol, flow, source, destination, sourceRole, destinationRole;
    QString operation, object, state = "UNRESOLVED", completion = "OPEN";
    QVector<quint32> frames;
    QVector<QString> events, findings;
    QVector<Transition> transitions;
    double startMs = 0, endMs = 0;
    bool startedHere = true, negative = false;
};
struct Finding {
    QString id, rule, protocol, category, severity = "NOTICE", expected, observed, explanation, basis;
    QVector<quint32> frames;
    QVector<Evidence> evidence;
};
QString measurementKey(const Event&);
void transition(Transaction&, const Event&, const QString& state, const QString& expected = {});
}
