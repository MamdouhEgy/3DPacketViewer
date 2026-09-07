// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/Model.h"
namespace sspa
{
struct DecodedField {
    QString name;
    Value value;
    int parent = -1;
    QVector<int> ancestors;
};
struct DecodedGroup {
    QString protocol;
    int node = -1;
    QVector<DecodedField> fields;
};
struct DecodedPacket {
    quint32 frame = 0;
    double timeMs = 0;
    QVector<DecodedField> common;
    QVector<DecodedGroup> groups;
    bool malformed = false, modbusRequest = false, modbusResponse = false;
    QString diagnostic;
};
const QMap<QString, QString>& semanticFields();
QVector<Event> normalize(const DecodedPacket&);
}
