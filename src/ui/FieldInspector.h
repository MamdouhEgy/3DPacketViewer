// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/PacketModel.h"
#include <QPlainTextEdit>
namespace pv
{
class FieldInspector : public QPlainTextEdit
{
public:
    explicit FieldInspector(QWidget* parent = nullptr)
        : QPlainTextEdit(parent)
    {
        setReadOnly(true);
    }
    static QString describe(const PacketModel&, const Field&);
    void showField(const PacketModel&, const Field*);
};
}
