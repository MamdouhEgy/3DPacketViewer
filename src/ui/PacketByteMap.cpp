// SPDX-License-Identifier: GPL-2.0-or-later
#include "PacketByteMap.h"
#include "FieldInspector.h"
#include <QPainter>
#include <QScrollBar>
#include <QMouseEvent>
#include <QToolTip>
#include <algorithm>
namespace pv
{
PacketByteMap::PacketByteMap(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    setObjectName("packetByteMap");
    setMinimumSize(440, 280);
    setMouseTracking(true);
    viewport()->setMouseTracking(true);
    setFocusPolicy(Qt::StrongFocus);
    connect(verticalScrollBar(), &QScrollBar::valueChanged, this, [this] {
        QToolTip::hideText();
        viewport()->update();
    });
}
double PacketByteMap::bitWidth() const
{
    return std::max(1.0, (viewport()->width() - gutter - 12.0) / rowBits);
}
QRectF PacketByteMap::rectFor(BitRange bits) const
{
    return { gutter + (bits.start % rowBits) * bitWidth(),
        header + (double(bits.start / rowBits) - verticalScrollBar()->value()) * rowHeight + 6,
        bits.length * bitWidth(), 48 };
}
void PacketByteMap::setData(Packet p, int s)
{
    packet = std::move(p);
    source = s;
    selected = -1;
    verticalScrollBar()->setValue(0);
    rebuild();
}
void PacketByteMap::setRowBits(int bits)
{
    if (bits != 32 && bits != 64 && bits != 128)
        return;
    rowBits = bits;
    rebuild();
    revealSelection();
}
void PacketByteMap::rebuild()
{
    Layout layout;
    layout.source = source;
    layout.rowBits = rowBits;
    layout.wireView = true;
    geometry = packet ? PacketGeometryEngine::build(*packet, layout) : Geometry();
    updateScroll();
    viewport()->update();
}
void PacketByteMap::updateScroll()
{
    // Scroll in rows rather than pixels to bound integer values for large sources.
    const int rows
        = geometry.tiles.empty() ? 0 : int((geometry.tiles.back().bits.end() + rowBits - 1) / rowBits);
    const int page = std::max(1, (viewport()->height() - header) / rowHeight);
    verticalScrollBar()->setRange(0, std::max(0, rows - page));
    verticalScrollBar()->setPageStep(page);
    verticalScrollBar()->setSingleStep(1);
}
void PacketByteMap::resizeEvent(QResizeEvent* event)
{
    QAbstractScrollArea::resizeEvent(event);
    updateScroll();
}
void PacketByteMap::selectField(int id)
{
    selected = id;
    revealSelection();
    viewport()->update();
}
void PacketByteMap::setProtocolFocus(int id)
{
    protocolFocus = id;
    viewport()->update();
}
void PacketByteMap::revealSelection()
{
    const auto* f = packet ? packet->field(selected) : nullptr;
    if (!f || f->source != source || f->generated || f->ranges.empty())
        return;
    const int row = int(f->ranges.front().start / rowBits);
    const int first = verticalScrollBar()->value();
    if (row < first || row >= first + verticalScrollBar()->pageStep())
        verticalScrollBar()->setValue(std::max(0, row - 1));
}
bool PacketByteMap::highlighted(uint64_t bit) const
{
    const auto* f = packet ? packet->field(selected) : nullptr;
    if (!f || f->source != source || f->generated)
        return false;
    for (auto range : f->ranges)
        if (bit >= range.start && bit < range.end())
            return true;
    return false;
}
QRectF PacketByteMap::fieldRect(int id) const
{
    for (const auto& tile : geometry.tiles)
        if (tile.field == id) {
            auto rect = rectFor(tile.bits);
            if (rect.top() >= header && rect.bottom() <= viewport()->height())
                return rect;
        }
    return {};
}
int PacketByteMap::fieldAt(QPoint point) const
{
    if (point.y() < header || point.x() < gutter)
        return -1;
    const uint64_t row = verticalScrollBar()->value() + (point.y() - header) / rowHeight;
    const auto begin = std::lower_bound(geometry.tiles.begin(), geometry.tiles.end(), row * rowBits,
        [](const Tile& tile, uint64_t bit) { return tile.bits.end() <= bit; });
    for (auto it = begin; it != geometry.tiles.end() && it->bits.start / rowBits == row; ++it)
        if (rectFor(it->bits).contains(point))
            return it->field;
    return -1;
}
void PacketByteMap::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton)
        emit fieldClicked(fieldAt(event->position().toPoint()));
}
void PacketByteMap::mouseMoveEvent(QMouseEvent* event)
{
    const auto* f = packet ? packet->field(fieldAt(event->position().toPoint())) : nullptr;
    if (f)
        QToolTip::showText(event->globalPosition().toPoint(),
            "<pre>" + FieldInspector::describe(*packet, *f).toHtmlEscaped() + "</pre>", viewport());
    else
        QToolTip::hideText();
}
void PacketByteMap::leaveEvent(QEvent*)
{
    QToolTip::hideText();
}
void PacketByteMap::paintEvent(QPaintEvent*)
{
    QPainter p(viewport());
    p.fillRect(viewport()->rect(), QColor("#f6f8fb"));
    p.setPen(QColor("#263449"));
    if (!packet || source < 0 || source >= packet->sources.size() || geometry.tiles.empty()) {
        p.drawText(viewport()->rect().adjusted(20, 20, -20, -20), Qt::TextWordWrap,
            packet && !packet->diagnostic.isEmpty() ? packet->diagnostic
                                                    : "No captured bytes in this data source.");
        return;
    }
    const auto& data = packet->sources[source];
    p.drawText(10, 21, "Byte offset");
    p.drawText(10, 41, "hex / dec");
    for (int byte = 0; byte < rowBits / 8; ++byte) {
        const auto x = gutter + byte * 8 * bitWidth();
        p.drawText(QRectF(x, 4, 8 * bitWidth(), 20), Qt::AlignCenter, QString("+%1 byte").arg(byte));
        for (int bit = 0; bit < 8; ++bit) {
            const auto bx = x + bit * bitWidth();
            if (bitWidth() >= 9)
                p.drawText(QRectF(bx, 27, bitWidth(), 18), Qt::AlignCenter, QString::number(7 - bit));
            p.drawLine(QPointF(bx, 48), QPointF(bx, bit % 8 == 0 ? 57 : 52));
        }
    }
    const uint64_t first = uint64_t(verticalScrollBar()->value()) * rowBits;
    const uint64_t last = first + uint64_t((viewport()->height() - header) / rowHeight + 2) * rowBits;
    const auto begin = std::lower_bound(geometry.tiles.begin(), geometry.tiles.end(), first,
        [](const Tile& tile, uint64_t bit) { return tile.bits.end() <= bit; });
    static const QColor colors[] = { QColor("#56b4e9"), QColor("#e69f00"), QColor("#009e73"),
        QColor("#cc79a7"), QColor("#f0e442"), QColor("#0072b2"), QColor("#d55e00") };
    p.save();
    p.setClipRect(QRect(0, header, viewport()->width(), viewport()->height() - header));
    for (auto it = begin; it != geometry.tiles.end() && it->bits.start < last; ++it) {
        const auto rect = rectFor(it->bits);
        const auto* f = packet->field(it->field);
        QColor color("#e2e5ea");
        if (f) {
            const auto category = colors[unsigned(it->layer) % 7];
            color = QColor((category.red() + 3 * 255) / 4, (category.green() + 3 * 255) / 4,
                (category.blue() + 3 * 255) / 4);
        }
        const bool dim = protocolFocus >= 0 && (!f || f->protocolNode != protocolFocus);
        if (dim)
            color = QColor("#edf0f4");
        p.fillRect(rect, color);
        p.setPen(QPen(QColor("#728095"), 1));
        p.drawRect(rect);
        if (rect.width() > 34) {
            p.setPen(dim ? QColor("#647084") : QColor("#162438"));
            const QString name = f ? f->abbreviation : "Unmapped wire region";
            const QString value = f ? f->display : "No canonical field";
            const QRectF text = rect.adjusted(5, 3, -5, -3);
            p.drawText(text, Qt::AlignTop | Qt::AlignLeft,
                fontMetrics().elidedText(name, Qt::ElideRight, int(text.width())));
            p.drawText(text, Qt::AlignBottom | Qt::AlignLeft,
                fontMetrics().elidedText(value, Qt::ElideRight, int(text.width())));
        }
    }
    const auto* selectedField = packet->field(selected);
    for (uint64_t bit = first; bit < std::min(last, uint64_t(data.bytes.size()) * 8); bit += rowBits) {
        const double y = header + double((bit - first) / rowBits) * rowHeight;
        p.setPen(QColor("#263449"));
        p.drawText(QRectF(4, y + 10, gutter - 12, 20), Qt::AlignRight,
            QString("0x%1").arg(bit / 8, 4, 16, QChar('0')));
        p.drawText(QRectF(4, y + 31, gutter - 12, 20), Qt::AlignRight, QString::number(bit / 8));
        // Highlight ranges independently of canonical ownership, so parents and aliases remain exact.
        if (selectedField && selectedField->source == source && !selectedField->generated) {
            for (auto range : selectedField->ranges) {
                const uint64_t lo = std::max(bit, range.start), hi = std::min(bit + rowBits, range.end());
                if (lo < hi) {
                    p.setPen(QPen(QColor("#111827"), 2));
                    p.drawRect(rectFor({ lo, hi - lo }).adjusted(1, 1, -1, -1));
                    p.fillRect(QRectF(gutter + (lo - bit) * bitWidth(), y + 55, (hi - lo) * bitWidth(), 4),
                        QColor("#111827"));
                }
            }
        }
        for (int b = 0; b < rowBits && bit + b < uint64_t(data.bytes.size()) * 8; ++b) {
            const uint64_t at = bit + b;
            const double x = gutter + b * bitWidth();
            const bool mark = highlighted(at);
            if (mark)
                p.fillRect(QRectF(x, y + 62, bitWidth(), 18), QColor("#ffe08a"));
            p.setPen(QColor("#263449"));
            if (bitWidth() >= 9) {
                const auto value = uint8_t(data.bytes[int(at / 8)]);
                p.drawText(QRectF(x, y + 62, bitWidth(), 18), Qt::AlignCenter,
                    value & (1 << (7 - at % 8)) ? "1" : "0");
            }
        }
    }
    p.restore();
}
}
