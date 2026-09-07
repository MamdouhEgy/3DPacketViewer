// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "PacketModel.h"
namespace pv
{
class FieldRangeResolver
{
public:
    static void resolve(Field& field, const QVector<DataSource>& sources);
};
}
