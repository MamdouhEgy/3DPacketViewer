// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/PacketModel.h"
#include <QAbstractScrollArea>
namespace pv
{
class RawByteView : public QAbstractScrollArea
{
public:
    explicit RawByteView(QWidget* parent = nullptr);
    void setData(Packet, int source, int field);
    bool highlighted(uint64_t bit) const;

protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;

private:
    Packet packet;
    int source = -1, selected = -1;
    void updateScroll();
};
}
