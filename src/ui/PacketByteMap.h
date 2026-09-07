// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/PacketGeometryEngine.h"
#include <QAbstractScrollArea>
namespace pv
{
// A source-relative, orthogonal map. Geometry owns no Wireshark pointers.
class PacketByteMap : public QAbstractScrollArea
{
    Q_OBJECT
public:
    explicit PacketByteMap(QWidget* parent = nullptr);
    void setData(Packet, int source);
    void setRowBits(int);
    void selectField(int);
    void setProtocolFocus(int);
    void revealSelection();
    int fieldAt(QPoint) const;
    QRectF fieldRect(int) const;
    bool highlighted(uint64_t) const;
    QString diagnostic() const
    {
        return geometry.diagnostic;
    }
signals:
    void fieldClicked(int);

protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void leaveEvent(QEvent*) override;

private:
    Packet packet;
    Geometry geometry;
    int source = -1, selected = -1, protocolFocus = -1, rowBits = 64;
    static constexpr int gutter = 86, header = 58, rowHeight = 82;
    double bitWidth() const;
    QRectF rectFor(BitRange) const;
    void rebuild();
    void updateScroll();
};
}
