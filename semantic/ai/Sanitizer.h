// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/Context.h"
#include <QJsonObject>
namespace sspa
{
struct SanitizedContext {
    QJsonObject json;
    QSet<quint32> evidenceFrames;
    QSet<QString> findingIds;
    QString error;
};
class Sanitizer
{
public:
    SanitizedContext build(const Context&);
    SanitizedContext build(const Comparison&);

private:
    QMap<QString, QString> identities;
    QString token(const QString&, const QString&);
    QJsonObject encode(const Context&);
};
QJsonObject localEvent(const Event&);
QJsonObject localTransaction(const Transaction&);
QJsonObject localFinding(const Finding&);
QJsonObject localReport(const Engine&, bool captureBoundary);
}
