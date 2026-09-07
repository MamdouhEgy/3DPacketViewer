// SPDX-License-Identifier: GPL-2.0-or-later
#include "CameraController.h"
#include <algorithm>
#include <cmath>
namespace pv
{
void CameraController::reset()
{
    rotation = QQuaternion::fromEulerAngles(35, -18, -8);
}
void CameraController::fit(QVector3D low, QVector3D high)
{
    center = (low + high) * 0.5f;
    radius = std::max(1.f, (high - low).length() * 0.5f);
    distance = radius * 3.5f;
}
void CameraController::orbit(QPointF d)
{
    const auto qx = QQuaternion::fromAxisAndAngle(0, 1, 0, float(d.x()) * 0.4f);
    const auto qy = QQuaternion::fromAxisAndAngle(1, 0, 0, float(d.y()) * 0.4f);
    rotation = (qy * qx * rotation).normalized();
}
void CameraController::pan(QPointF d, QSize size)
{
    const float scale = distance * 0.75f / std::max(1, size.height());
    center += rotation.conjugated().rotatedVector(QVector3D(-float(d.x()) * scale, float(d.y()) * scale, 0));
}
void CameraController::zoom(float steps)
{
    if (!std::isfinite(steps))
        return;
    distance = std::clamp(distance * std::exp(-std::clamp(steps, -20.f, 20.f) * 0.12f), 0.1f, 1e8f);
}
QMatrix4x4 CameraController::matrix(QSize size) const
{
    const float aspect = float(std::max(1, size.width())) / std::max(1, size.height());
    QMatrix4x4 p, v;
    const float near = std::max(0.001f, distance * 0.0001f);
    const float far = std::max(distance + radius * 8, near + 1);
    if (orthographic) {
        const float span = distance * 0.41421356f;
        p.ortho(-span * aspect, span * aspect, -span, span, near, far);
    } else
        p.perspective(45, aspect, near, far);
    v.translate(0, 0, -distance);
    v.rotate(rotation);
    v.translate(-center);
    return p * v;
}
}
