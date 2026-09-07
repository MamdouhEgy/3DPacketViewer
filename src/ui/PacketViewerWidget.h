// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "rendering/PacketRenderer.h"
#include "FieldInspector.h"
#include "RawByteView.h"
#include <QTreeWidget>
#include <QComboBox>
#include <QLabel>
namespace pv
{
class PacketViewerWidget : public QWidget
{
    Q_OBJECT
public:
    explicit PacketViewerWidget(QWidget* parent = nullptr);
    void setPacket(Packet);
    void showDiagnostic(QString);
    void selectField(int);
    Packet model;
    PacketRenderer* renderer;
    RawByteView* bytes;
    FieldInspector* inspector;
    QTreeWidget* tree;
    QComboBox* sources;
    QLabel* status;
    bool showGenerated = true;

private:
    QVector<QTreeWidgetItem*> items;
    void filterGenerated();
    void updateStatus();
};
}
