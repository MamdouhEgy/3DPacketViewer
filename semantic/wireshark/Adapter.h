// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/Engine.h"
#include <QObject>
#include <QTimer>
#include <QPointer>
class QTreeView;
class QWidget;
namespace sspa
{
class Adapter final : public QObject
{
    Q_OBJECT
public:
    explicit Adapter(QWidget* host, QObject* parent);
    ~Adapter() override;
    Engine engine;
    bool captureBoundary = true;
    QList<int> selectedFrames;
    void retap();
    static void navigate(quint32);
    static void filter(const QVector<quint32>&);
    void changed();
signals:
    void updated();
    void selectionChanged();
    void invalidated();
private slots:
    void framesChanged(QList<int>);
    void captureChanged();

private:
    QPointer<QTreeView> packetList;
    bool registered = false;
    QTimer redraw;
};
}
