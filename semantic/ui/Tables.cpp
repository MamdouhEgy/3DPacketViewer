// SPDX-License-Identifier: GPL-2.0-or-later
#include "Tables.h"
namespace sspa
{
int SemanticTable::rowCount(const QModelIndex& p) const
{
    return p.isValid()         ? 0
        : kind == Transactions ? engine.transactions.size()
        : kind == Events       ? engine.events.size()
                               : engine.findings.size();
}
int SemanticTable::columnCount(const QModelIndex& p) const
{
    return p.isValid() ? 0 : kind == Transactions ? 10 : kind == Events ? 8 : 5;
}
QVariant SemanticTable::headerData(int n, Qt::Orientation o, int role) const
{
    if (role != Qt::DisplayRole)
        return {};
    if (o == Qt::Vertical)
        return n + 1;
    const QStringList labels = kind == Transactions ? QStringList { "Transaction", "Protocol", "Operation",
        "Source / role", "Destination / role", "Object", "State", "Completion", "Duration (ms)", "Frames" }
        : kind == Events ? QStringList { "Frame", "Time (ms)", "Protocol", "Event", "Source", "Destination",
              "Object", "Value" }
                         : QStringList { "Rule", "Protocol", "Category", "Severity", "Frames" };
    return labels.value(n);
}
QVariant SemanticTable::data(const QModelIndex& i, int role) const
{
    if (!i.isValid() || i.row() >= rowCount() || role != Qt::DisplayRole)
        return {};
    auto frames = [](const QVector<quint32>& values) {
        QStringList s;
        for (auto f : values)
            s << QString::number(f);
        return s.join(", ");
    };
    if (kind == Transactions) {
        const auto& t = engine.transactions[i.row()];
        switch (i.column()) {
        case 0:
            return t.id;
        case 1:
            return t.protocol;
        case 2:
            return t.operation;
        case 3:
            return t.source + " / " + t.sourceRole;
        case 4:
            return t.destination + " / " + t.destinationRole;
        case 5:
            return t.object;
        case 6:
            return t.state;
        case 7:
            return boundary && t.completion == "OPEN" ? "INCOMPLETE_CAPTURE_BOUNDARY" : t.completion;
        case 8:
            return t.endMs >= t.startMs ? QVariant(t.endMs - t.startMs)
                                        : QVariant("Unavailable (timestamp order)");
        case 9:
            return frames(t.frames);
        }
    }
    if (kind == Events) {
        const auto& e = engine.events[i.row()];
        switch (i.column()) {
        case 0:
            return e.frame;
        case 1:
            return e.timeMs;
        case 2:
            return e.protocol;
        case 3:
            return e.type;
        case 4:
            return e.source;
        case 5:
            return e.destination;
        case 6:
            return e.object;
        case 7:
            return e.has("value") ? e.values["value"].data : QVariant();
        }
    }
    if (kind == Findings) {
        const auto& f = engine.findings[i.row()];
        switch (i.column()) {
        case 0:
            return f.rule;
        case 1:
            return f.protocol;
        case 2:
            return f.category;
        case 3:
            return f.severity;
        case 4:
            return frames(f.frames);
        }
    }
    return {};
}
}
