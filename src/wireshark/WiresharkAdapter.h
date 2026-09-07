// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "ui/PacketViewerWidget.h"
#include <QObject>
namespace pv
{
class WiresharkAdapter : public QObject
{
    Q_OBJECT
public:
    explicit WiresharkAdapter(QWidget* host, PacketViewerWidget* viewer);
public slots:
    void framesChanged(QList<int> frames);
    void captureChanged();
    void fieldChanged();
    void refresh();
    void syncField();

private:
    PacketViewerWidget* viewer;
    uint64_t generation = 0;
    bool multiple = false;
};
}
