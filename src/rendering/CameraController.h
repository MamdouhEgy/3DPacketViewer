// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QMatrix4x4>
#include <QQuaternion>
#include <QPointF>
#include <QSize>
namespace pv
{
class CameraController
{
public:
    QVector3D center;
    QQuaternion rotation;
    float distance = 80, radius = 35;
    bool orthographic = false;
    void reset();
    void fit(QVector3D low, QVector3D high);
    void orbit(QPointF delta);
    void pan(QPointF delta, QSize viewport);
    void zoom(float steps);
    QMatrix4x4 matrix(QSize viewport) const;
};
}
