// SPDX-License-Identifier: GPL-2.0-or-later
#include "Model.h"
#include <cmath>
namespace sspa
{
std::optional<double> Event::number(const QString& key) const
{
    const auto it = values.constFind(key);
    if (it == values.cend())
        return {};
    const auto type = it->data.metaType().id();
    if (type != QMetaType::Double && type != QMetaType::LongLong && type != QMetaType::Bool
        && type != QMetaType::Int && type != QMetaType::UInt && type != QMetaType::ULongLong)
        return {};
    if ((type == QMetaType::LongLong
            && (it->data.toLongLong() < -9007199254740991LL || it->data.toLongLong() > 9007199254740991LL))
        || (type == QMetaType::ULongLong && it->data.toULongLong() > 9007199254740991ULL))
        return {};
    bool ok = false;
    const double value = it->data.toDouble(&ok);
    return ok && std::isfinite(value) ? std::optional<double>(value) : std::nullopt;
}
qint64 Event::integer(const QString& key, qint64 fallback) const
{
    const auto n = number(key);
    return n && *n >= -9007199254740991.0 && *n <= 9007199254740991.0 && std::floor(*n) == *n ? qint64(*n)
                                                                                              : fallback;
}
QString Event::text(const QString& key) const
{
    return values.value(key).data.toString();
}
QString measurementKey(const Event& e)
{
    return e.protocol + ":" + e.flow + ":" + e.source + ":" + e.publisher + ":" + e.object + ":"
        + QString::number(e.integer("common_address")) + ":" + e.text("measurement_kind");
}
void transition(Transaction& t, const Event& e, const QString& state, const QString& expected)
{
    t.transitions.push_back({ t.state, state, e.type, expected, e.frame, e.timeMs });
    t.state = state;
    t.endMs = e.timeMs;
    if (!t.frames.contains(e.frame))
        t.frames.push_back(e.frame);
    t.events.push_back(e.id);
}
}
