// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "wireshark/Adapter.h"
#include "Tables.h"
#include "AiPanel.h"
#include <QWidget>
class QTableView;
class QPlainTextEdit;
class QLabel;
class QComboBox;
class QSpinBox;
class QDoubleSpinBox;
class QLineEdit;
namespace sspa
{
class Viewer final : public QWidget
{
    Q_OBJECT
public:
    explicit Viewer(QWidget* host);
    Adapter adapter;
    AiPanel* ai;
    void refresh();

private:
    SemanticTable *transactionModel, *eventModel, *findingModel;
    QTableView *transactions, *events, *findings;
    QPlainTextEdit *details, *contextView;
    QLabel* status;
    QComboBox* mode;
    QSpinBox *first, *last, *otherFirst, *otherLast, *maxEvents;
    QDoubleSpinBox *before, *after;
    QLineEdit* compareIdentity;
    QVector<quint32> navigationFrames;
    SanitizedContext makeContext();
    Selector selector(int mode, bool baseline = true) const;
    void showTransaction(int);
    void showEvent(int);
    void showFinding(int);
};
}
