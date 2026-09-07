// SPDX-License-Identifier: GPL-2.0-or-later
#include "PacketRenderer.h"
#include "core/SelectionController.h"
#include "ui/FieldInspector.h"
#include <QOpenGLContext>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QPainter>
#include <QToolTip>
#include <QElapsedTimer>
#include <QDateTime>
#include <QSet>
static void initializeResources()
{
    Q_INIT_RESOURCE(shaders);
}
namespace pv
{
class PacketOverlay : public QWidget
{
public:
    explicit PacketOverlay(PacketRenderer* renderer)
        : QWidget(renderer)
        , renderer(renderer)
    {
        setObjectName("packetLabels");
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        setAttribute(Qt::WA_TranslucentBackground);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter painter(this);
        renderer->drawOverlay(painter);
    }

private:
    PacketRenderer* renderer;
};
static QColor category(int layer)
{
    static const QColor palette[] = { QColor("#56b4e9"), QColor("#e69f00"), QColor("#009e73"),
        QColor("#cc79a7"), QColor("#f0e442"), QColor("#0072b2"), QColor("#d55e00") };
    return palette[unsigned(layer) % 7];
}
PacketRenderer::PacketRenderer(QWidget* parent)
    : QOpenGLWidget(parent)
    , buffer(QOpenGLBuffer::VertexBuffer)
{
    initializeResources();
    overlay = new PacketOverlay(this);
    overlay->show();
    QSurfaceFormat fmt;
    fmt.setRenderableType(QSurfaceFormat::OpenGL);
    fmt.setVersion(2, 1);
    fmt.setProfile(QSurfaceFormat::NoProfile);
    fmt.setDepthBufferSize(24);
    fmt.setSamples(4);
    setFormat(fmt);
    setMouseTracking(true);
    setFocusPolicy(Qt::StrongFocus);
    setMinimumSize(400, 300);
    camera.reset();
}
PacketRenderer::~PacketRenderer()
{
    cleanup();
}
void PacketRenderer::cleanup()
{
    if (context()) {
        disconnect(context(), nullptr, this, nullptr);
        makeCurrent();
        buffer.destroy();
        shader.removeAllShaders();
        doneCurrent();
    }
    ready = false;
}
void PacketRenderer::initializeGL()
{
    initializeOpenGLFunctions();
    connect(
        context(), &QOpenGLContext::aboutToBeDestroyed, this, &PacketRenderer::cleanup, Qt::DirectConnection);
    if (!shader.addShaderFromSourceFile(QOpenGLShader::Vertex, ":/3dpv/shaders/packet.vert")
        || !shader.addShaderFromSourceFile(QOpenGLShader::Fragment, ":/3dpv/shaders/packet.frag")
        || !shader.link()) {
        glError = "OpenGL shader failure: " + shader.log();
        emit statusChanged();
        return;
    }
    if (!buffer.create()) {
        glError = "OpenGL vertex buffer creation failed";
        emit statusChanged();
        return;
    }
    ready = true;
    dirty = true;
    glEnable(GL_DEPTH_TEST);
}
void PacketRenderer::setPacket(Packet p)
{
    packet = std::move(p);
    selected = -1;
    submitted = QDateTime::currentMSecsSinceEpoch();
    firstRenderMs = 0;
    if (!packet || layout.source >= packet->sources.size())
        layout.source = 0;
    rebuild(true);
}
void PacketRenderer::rebuild(bool fit)
{
    geometry = packet ? PacketGeometryEngine::build(*packet, layout) : Geometry {};
    dirty = true;
    if (fit)
        fitAll();
    update();
}
void PacketRenderer::setSelected(int id)
{
    selected = id;
    dirty = true;
    update();
}
void PacketRenderer::fitAll()
{
    camera.fit(geometry.low, geometry.high);
    QVector3D extent;
    for (int i = 0; i < 8; ++i) {
        const QVector3D corner(i & 1 ? geometry.high.x() : geometry.low.x(),
            i & 2 ? geometry.high.y() : geometry.low.y(), i & 4 ? geometry.high.z() : geometry.low.z());
        const auto p = camera.rotation.rotatedVector(corner - camera.center);
        for (int k = 0; k < 3; ++k)
            extent[k] = std::max(extent[k], std::abs(p[k]));
    }
    const float aspect = float(std::max(1, width())) / std::max(1, height());
    camera.distance
        = std::max(1.f, 1.2f * (std::max(extent.x() / aspect, extent.y()) / 0.41421356f + extent.z()));
    update();
}
void PacketRenderer::fitSelected()
{
    bool found = false;
    QVector3D low, high;
    for (const auto& t : geometry.tiles) {
        if (t.field != selected || selected < 0)
            continue;
        if (!found) {
            low = t.low;
            high = t.high;
            found = true;
        } else
            for (int k = 0; k < 3; ++k) {
                low[k] = std::min(low[k], t.low[k]);
                high[k] = std::max(high[k], t.high[k]);
            }
    }
    if (found)
        camera.fit(low, high);
    else
        fitAll();
    update();
}
void PacketRenderer::upload()
{
    QElapsedTimer timer;
    timer.start();
    struct Vertex {
        float x, y, z, r, g, b;
    };
    QVector<Vertex> vertices;
    vertices.reserve(geometry.tiles.size() * 36);
    constexpr int faces[6][6] = { { 4, 5, 6, 4, 6, 7 }, { 0, 2, 1, 0, 3, 2 }, { 0, 1, 5, 0, 5, 4 },
        { 3, 7, 6, 3, 6, 2 }, { 0, 4, 7, 0, 7, 3 }, { 1, 2, 6, 1, 6, 5 } };
    for (const auto& t : geometry.tiles) {
        auto c = t.field < 0 ? QColor("#777f89") : category(t.layer);
        if (t.field == selected && selected >= 0)
            c = QColor("#ffffff");
        const auto a = t.low, b = t.high;
        const QVector3D corners[] = { { a.x(), a.y(), a.z() }, { b.x(), a.y(), a.z() },
            { b.x(), b.y(), a.z() }, { a.x(), b.y(), a.z() }, { a.x(), a.y(), b.z() },
            { b.x(), a.y(), b.z() }, { b.x(), b.y(), b.z() }, { a.x(), b.y(), b.z() } };
        for (int face = 0; face < 6; ++face)
            for (int vertexIndex : faces[face]) {
                const float shade = face == 0 ? 1.f : 0.60f;
                const auto p = corners[vertexIndex];
                vertices.push_back({ p.x(), p.y(), p.z(), float(c.redF()) * shade, float(c.greenF()) * shade,
                    float(c.blueF()) * shade });
            }
    }
    vertexCount = vertices.size();
    buffer.bind();
    buffer.allocate(vertices.constData(), int(vertices.size() * sizeof(Vertex)));
    buffer.release();
    uploadMs = timer.nsecsElapsed() / 1e6;
    dirty = false;
}
void PacketRenderer::paintGL()
{
    glClearColor(0.055f, 0.075f, 0.11f, 1);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    if (ready) {
        if (dirty)
            upload();
        glEnable(GL_DEPTH_TEST);
        shader.bind();
        buffer.bind();
        shader.setUniformValue("mvp", camera.matrix(size()));
        shader.enableAttributeArray("position");
        shader.enableAttributeArray("color");
        shader.setAttributeBuffer("position", GL_FLOAT, 0, 3, 6 * sizeof(float));
        shader.setAttributeBuffer("color", GL_FLOAT, 3 * sizeof(float), 3, 6 * sizeof(float));
        glDrawArrays(GL_TRIANGLES, 0, vertexCount);
        shader.disableAttributeArray("position");
        shader.disableAttributeArray("color");
        buffer.release();
        shader.release();
    }
    glDisable(GL_DEPTH_TEST);
    overlay->update();
    ++renderCount;
    if (!firstRenderMs && submitted) {
        firstRenderMs = std::max<qint64>(1, QDateTime::currentMSecsSinceEpoch() - submitted);
        emit statusChanged();
    }
}
void PacketRenderer::resizeEvent(QResizeEvent* event)
{
    QOpenGLWidget::resizeEvent(event);
    overlay->setGeometry(rect());
}
void PacketRenderer::drawOverlay(QPainter& painter)
{
    painter.setRenderHint(QPainter::TextAntialiasing);
    painter.setPen(Qt::white);
    if (!glError.isEmpty())
        painter.drawText(rect().adjusted(15, 15, -15, -15), Qt::TextWordWrap, glError);
    else if (!packet || !packet->diagnostic.isEmpty())
        painter.drawText(15, 24, packet ? packet->diagnostic : "No capture loaded.");
    if (!geometry.diagnostic.isEmpty())
        painter.drawText(15, 45, geometry.diagnostic);
    // Selection has an outline as well as a categorical color change.
    if (selected >= 0 && ready) {
        const auto matrix = camera.matrix(size());
        painter.setPen(QPen(Qt::white, 2));
        for (const auto& t : geometry.tiles)
            if (t.field == selected) {
                QPolygonF outline;
                const QVector3D corners[]
                    = { { t.low.x(), t.low.y(), t.high.z() }, { t.high.x(), t.low.y(), t.high.z() },
                          { t.high.x(), t.high.y(), t.high.z() }, { t.low.x(), t.high.y(), t.high.z() } };
                for (auto corner : corners) {
                    auto p = matrix.map(corner);
                    outline << QPointF((p.x() + 1) * width() / 2, (1 - p.y()) * height() / 2);
                }
                painter.drawPolygon(outline);
            }
        painter.setPen(Qt::white);
    }
    if (labels && packet && ready) {
        const auto matrix = camera.matrix(size());
        QVector<QRectF> occupiedLabels;
        QSet<int> drawn;
        int count = 0;
        QSet<int> namedLayers;
        for (const auto& t : geometry.tiles) {
            if (t.field < 0 || namedLayers.contains(t.layer) || namedLayers.size() >= 32)
                continue;
            auto p = matrix * QVector4D(t.low.x(), t.high.y(), t.high.z(), 1);
            if (p.w() <= 0)
                continue;
            p /= p.w();
            QPointF point((p.x() + 1) * width() / 2, (1 - p.y()) * height() / 2);
            const QString name = packet->fields[t.field].protocol;
            if (!name.isEmpty() && rect().contains(point.toPoint())) {
                const auto label = QRectF(
                    point + QPointF(-5, -25), QSizeF(painter.fontMetrics().horizontalAdvance(name) + 12, 20));
                bool overlaps = false;
                for (const auto& placed : occupiedLabels)
                    overlaps |= placed.intersects(label);
                if (overlaps)
                    continue;
                occupiedLabels.push_back(label.adjusted(-2, -2, 2, 2));
                painter.fillRect(label, QColor(10, 15, 22, 235));
                painter.drawText(label, Qt::AlignCenter, name);
            }
            namedLayers.insert(t.layer);
        }
        for (const auto& t : geometry.tiles) {
            if (count >= 100 || t.field < 0 || drawn.contains(t.field))
                continue;
            auto a = matrix * QVector4D(t.low.x(), t.high.y(), t.high.z(), 1);
            auto b = matrix * QVector4D(t.high, 1);
            if (a.w() <= 0 || b.w() <= 0)
                continue;
            a /= a.w();
            b /= b.w();
            QPointF point((a.x() + 1) * width() / 2, (1 - a.y()) * height() / 2);
            if (!rect().contains(point.toPoint()) || std::abs(b.x() - a.x()) * width() / 2 < 85)
                continue;
            const QString name = packet->fields[t.field].abbreviation;
            const QRectF box(
                point + QPointF(2, -16), QSizeF(std::min(180.f, std::abs(b.x() - a.x()) * width() / 2), 18));
            bool overlaps = false;
            for (const auto& placed : occupiedLabels)
                overlaps |= placed.intersects(box);
            if (overlaps)
                continue;
            occupiedLabels.push_back(box.adjusted(-2, -2, 2, 2));
            painter.fillRect(box, QColor(10, 15, 22, 210));
            painter.drawText(box.adjusted(3, 0, -2, 0), Qt::AlignVCenter,
                painter.fontMetrics().elidedText(name, Qt::ElideRight, int(box.width() - 5)));
            drawn.insert(t.field);
            ++count;
        }
    }
    painter.drawText(
        12, height() - 12, "X: bit position in row · Y: wrapped row · Z: protocol separation (presentation)");
}
void PacketRenderer::mousePressEvent(QMouseEvent* e)
{
    last = press = e->position();
    moved = false;
    setFocus();
}
void PacketRenderer::mouseMoveEvent(QMouseEvent* e)
{
    const auto delta = e->position() - last;
    last = e->position();
    if ((e->position() - press).manhattanLength() > 3)
        moved = true;
    if (e->buttons() & Qt::LeftButton)
        camera.orbit(delta);
    else if (e->buttons() & (Qt::MiddleButton | Qt::RightButton))
        camera.pan(delta, size());
    else {
        const int tile = SelectionController::pick(geometry, camera.matrix(size()), e->position(), size());
        if (tile >= 0 && packet) {
            const auto* f = packet->field(geometry.tiles[tile].field);
            QToolTip::showText(e->globalPosition().toPoint(),
                f ? "<pre>" + FieldInspector::describe(*packet, *f).toHtmlEscaped() + "</pre>"
                  : "Unmapped wire region",
                this);
        } else
            QToolTip::hideText();
    }
    update();
}
void PacketRenderer::mouseReleaseEvent(QMouseEvent* e)
{
    if (e->button() != Qt::LeftButton || moved)
        return;
    const int tile = SelectionController::pick(geometry, camera.matrix(size()), e->position(), size());
    emit fieldClicked(tile < 0 ? -1 : geometry.tiles[tile].field);
}
void PacketRenderer::mouseDoubleClickEvent(QMouseEvent*)
{
    fitSelected();
}
void PacketRenderer::wheelEvent(QWheelEvent* e)
{
    camera.zoom(float(e->angleDelta().y()) / 120);
    update();
    e->accept();
}
}
