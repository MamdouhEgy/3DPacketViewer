// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/PacketGeometryEngine.h"
#include "CameraController.h"
#include <QOpenGLWidget>
#include <QOpenGLFunctions>
#include <QOpenGLShaderProgram>
#include <QOpenGLBuffer>
#include <QPainter>
namespace pv
{
class PacketRenderer : public QOpenGLWidget, protected QOpenGLFunctions
{
    Q_OBJECT
public:
    explicit PacketRenderer(QWidget* parent = nullptr);
    ~PacketRenderer() override;
    void setPacket(Packet packet);
    void rebuild(bool fit = false);
    void setSelected(int id);
    void fitAll();
    void fitSelected();
    Packet packet;
    Geometry geometry;
    Layout layout;
    CameraController camera;
    bool labels = true;
    int selected = -1;
    QString glError;
    double uploadMs = 0, firstRenderMs = 0;
    quint64 renderCount = 0;
signals:
    void fieldClicked(int id);
    void statusChanged();

protected:
    void initializeGL() override;
    void paintGL() override;
    void resizeEvent(QResizeEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void mouseReleaseEvent(QMouseEvent*) override;
    void mouseDoubleClickEvent(QMouseEvent*) override;
    void wheelEvent(QWheelEvent*) override;

private:
    friend class PacketOverlay;
    QWidget* overlay = nullptr;
    void drawOverlay(QPainter&);
    QOpenGLShaderProgram shader;
    QOpenGLBuffer buffer;
    QPointF last, press;
    bool moved = false, dirty = true, ready = false;
    int vertexCount = 0;
    qint64 submitted = 0;
    void upload();
    void cleanup();
};
}
