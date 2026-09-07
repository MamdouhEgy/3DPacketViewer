// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "PacketModel.h"
#include <QVector3D>
namespace pv
{
struct Tile {
    NodeId field = -1;
    int layer = 0, source = -1;
    BitRange bits;
    QVector3D low, high;
    bool operator==(const Tile&) const = default;
};
struct Geometry {
    QVector<Tile> tiles;
    QVector3D low, high;
    double buildMs = 0;
    QString diagnostic;
};
struct Layout {
    int rowBits = 64;
    float spacing = 3;
    bool exploded = true;
    bool wireView = false;
    int source = 0;
};
class PacketGeometryEngine
{
public:
    static Geometry build(const PacketModel&, const Layout&);
};
}
