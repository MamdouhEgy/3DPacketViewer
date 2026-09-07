// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "PacketGeometryEngine.h"
#include <QMatrix4x4>
#include <QPointF>
#include <QSize>
namespace pv
{
class SelectionController
{
public:
    static int pick(const Geometry&, const QMatrix4x4&, QPointF, QSize);
};
}
