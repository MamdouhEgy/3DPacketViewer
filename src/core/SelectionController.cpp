// SPDX-License-Identifier: GPL-2.0-or-later
#include "SelectionController.h"
#include <algorithm>
#include <cmath>
#include <limits>
namespace pv
{
int SelectionController::pick(const Geometry& g, const QMatrix4x4& matrix, QPointF point, QSize size)
{
    bool ok;
    const auto inverse = matrix.inverted(&ok);
    if (!ok || size.width() < 1 || size.height() < 1)
        return -1;
    const float x = float(2 * point.x() / size.width() - 1), y = float(1 - 2 * point.y() / size.height());
    const auto a = inverse.map(QVector3D(x, y, -1)), b = inverse.map(QVector3D(x, y, 1));
    const auto d = (b - a).normalized();
    float best = std::numeric_limits<float>::max();
    int hit = -1;
    for (int i = 0; i < g.tiles.size(); ++i) {
        float lo = 0, hi = best;
        for (int k = 0; k < 3; ++k) {
            if (std::abs(d[k]) < 1e-8f) {
                if (a[k] < g.tiles[i].low[k] || a[k] > g.tiles[i].high[k]) {
                    hi = -1;
                    break;
                }
            } else {
                float t1 = (g.tiles[i].low[k] - a[k]) / d[k], t2 = (g.tiles[i].high[k] - a[k]) / d[k];
                if (t1 > t2)
                    std::swap(t1, t2);
                lo = std::max(lo, t1);
                hi = std::min(hi, t2);
            }
        }
        if (lo <= hi && lo < best) {
            best = lo;
            hit = i;
        }
    }
    return hit;
}
}
