// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "ai/Provider.h"
#include <QWidget>
class QCheckBox;
class QComboBox;
class QPlainTextEdit;
class QLineEdit;
class QLabel;
class QListWidget;
class QSpinBox;
namespace sspa
{
class AiPanel final : public QWidget
{
    Q_OBJECT
public:
    explicit AiPanel(QWidget* parent = nullptr);
    void analyze(SanitizedContext, QString classification = "AI_DERIVED_OBSERVATION");
    void invalidate();
    OpenCodeGoProvider provider;
signals:
    void navigate(quint32);

private:
    QCheckBox* enable;
    QComboBox* models;
    QLineEdit* question;
    QPlainTextEdit* output;
    QLabel* status;
    QListWidget* evidence;
    QSpinBox *maxBytes, *maxTokens;
    QJsonObject lastResult;
    quint64 contextGeneration = 0;
};
}
