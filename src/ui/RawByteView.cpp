// SPDX-License-Identifier: GPL-2.0-or-later
#include "RawByteView.h"
#include <QPainter>
#include <QScrollBar>
#include <QFontDatabase>
namespace pv
{
RawByteView::RawByteView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    setMinimumHeight(140);
    connect(verticalScrollBar(), &QScrollBar::valueChanged, viewport(), qOverload<>(&QWidget::update));
}
void RawByteView::setData(Packet p, int s, int field)
{
    packet = std::move(p);
    source = s;
    selected = field;
    updateScroll();
    if (packet)
        if (const auto* f = packet->field(field))
            if (f->source == source && !f->ranges.empty())
                verticalScrollBar()->setValue(int(f->ranges.front().start / 8 / 8));
    viewport()->update();
}
bool RawByteView::highlighted(uint64_t bit) const
{
    if (!packet)
        return false;
    const auto* f = packet->field(selected);
    if (!f || f->source != source || f->generated)
        return false;
    for (const auto r : f->ranges)
        if (bit >= r.start && bit < r.end())
            return true;
    return false;
}
void RawByteView::updateScroll()
{
    const int rowHeight = fontMetrics().height() + 5;
    const int rows = packet && source >= 0 && source < packet->sources.size()
        ? int((packet->sources[source].bytes.size() + 7) / 8)
        : 0;
    verticalScrollBar()->setRange(0, std::max(0, rows - viewport()->height() / rowHeight));
    verticalScrollBar()->setPageStep(std::max(1, viewport()->height() / rowHeight));
}
void RawByteView::resizeEvent(QResizeEvent* e)
{
    QAbstractScrollArea::resizeEvent(e);
    updateScroll();
}
void RawByteView::paintEvent(QPaintEvent*)
{
    QPainter p(viewport());
    p.fillRect(viewport()->rect(), palette().base());
    if (!packet || source < 0 || source >= packet->sources.size()) {
        p.drawText(8, 20, "No data source available.");
        return;
    }
    const auto& bytes = packet->sources[source].bytes;
    const int h = fontMetrics().height() + 5, cw = fontMetrics().horizontalAdvance('0');
    for (int row = 0; row * h < viewport()->height(); ++row) {
        const uint64_t offset = uint64_t(row + verticalScrollBar()->value()) * 8;
        if (offset >= uint64_t(bytes.size()))
            break;
        p.setPen(palette().text().color());
        p.drawText(5, row * h + fontMetrics().ascent(), QString("%1").arg(offset, 8, 16, QChar('0')));
        for (int j = 0; j < 8 && offset + j < uint64_t(bytes.size()); ++j) {
            const auto value = uint8_t(bytes[int(offset + j)]);
            bool any = false;
            for (int bit = 0; bit < 8; ++bit)
                any |= highlighted((offset + j) * 8 + bit);
            const int x = (10 + j * 3) * cw;
            if (any)
                p.fillRect(x, row * h, 2 * cw, h, QColor("#f0e442"));
            p.setPen(any ? Qt::black : palette().text().color());
            p.drawText(x, row * h + fontMetrics().ascent(), QString("%1").arg(value, 2, 16, QChar('0')));
            for (int bit = 0; bit < 8; ++bit) {
                const int bx = (36 + j * 9 + bit) * cw;
                const bool mark = highlighted((offset + j) * 8 + bit);
                if (mark)
                    p.fillRect(bx, row * h, cw, h, QColor("#f0e442"));
                p.setPen(mark ? Qt::black : palette().text().color());
                p.drawText(bx, row * h + fontMetrics().ascent(), value & (1 << (7 - bit)) ? "1" : "0");
            }
        }
    }
}
}
