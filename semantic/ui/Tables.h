// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/Engine.h"
#include <QAbstractTableModel>
namespace sspa
{
class SemanticTable final : public QAbstractTableModel
{
public:
    enum Kind { Transactions, Events, Findings };
    SemanticTable(const Engine& e, Kind k, QObject* parent)
        : QAbstractTableModel(parent)
        , engine(e)
        , kind(k)
    {
    }
    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex&, int role = Qt::DisplayRole) const override;
    QVariant headerData(int, Qt::Orientation, int role = Qt::DisplayRole) const override;
    void refresh()
    {
        beginResetModel();
        endResetModel();
    }
    bool boundary = true;

private:
    const Engine& engine;
    Kind kind;
};
}
