// SPDX-License-Identifier: GPL-2.0-or-later
#include "AiPanel.h"
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QDialog>
#include <QDialogButtonBox>
#include <QJsonDocument>
#include <QJsonArray>
#include <QSettings>
#include <QSpinBox>
#include <QFileDialog>
#include <QSaveFile>
namespace sspa
{
AiPanel::AiPanel(QWidget* parent)
    : QWidget(parent)
    , provider(this)
{
    auto* layout = new QVBoxLayout(this);
    enable = new QCheckBox("Enable AI Explanation / Analysis", this);
    enable->setObjectName("enableAi");
    enable->setChecked(false);
    layout->addWidget(enable);
    auto* warning = new QLabel("OpenCode Go receives only the reviewed semantic request. Provider retention "
                               "policies vary by model. The core analyzer works offline.",
        this);
    warning->setWordWrap(true);
    layout->addWidget(warning);
    auto* form = new QFormLayout;
    layout->addLayout(form);
    auto* key = new QLineEdit(this);
    key->setEchoMode(QLineEdit::Password);
    key->setPlaceholderText(
        provider.keyConfigured() ? "OPENCODE_API_KEY available" : "Session key; never saved");
    form->addRow("API key (session only)", key);
    connect(key, &QLineEdit::editingFinished, this, [this, key] {
        if (!key->text().isEmpty()) {
            provider.setApiKey(key->text().toUtf8());
            key->clear();
            key->setPlaceholderText("Session key configured");
        }
    });
    models = new QComboBox(this);
    models->setObjectName("aiModel");
    form->addRow("OpenCode Go model", models);
    auto* controls = new QHBoxLayout;
    layout->addLayout(controls);
    auto* refresh = new QPushButton("Refresh Models", this);
    auto* test = new QPushButton("Test Connection", this);
    auto* cancel = new QPushButton("Cancel Request", this);
    controls->addWidget(refresh);
    controls->addWidget(test);
    controls->addWidget(cancel);
    maxBytes = new QSpinBox(this);
    maxBytes->setRange(4096, 2097152);
    maxBytes->setValue(262144);
    form->addRow("Maximum request bytes", maxBytes);
    maxTokens = new QSpinBox(this);
    maxTokens->setRange(128, 8192);
    maxTokens->setValue(2048);
    form->addRow("Maximum response tokens", maxTokens);
    question = new QLineEdit(this);
    question->setMaxLength(2000);
    question->setPlaceholderText("Explain temporal differences and plausible alternative causes.");
    form->addRow("Question (sent with context)", question);
    status = new QLabel("AI disabled. No provider requests are made.", this);
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    layout->addWidget(status);
    output = new QPlainTextEdit(this);
    output->setReadOnly(true);
    output->setObjectName("aiOutput");
    layout->addWidget(output, 1);
    evidence = new QListWidget(this);
    evidence->setMaximumHeight(110);
    layout->addWidget(evidence);
    auto* save = new QPushButton("Export AI result separately…", this);
    layout->addWidget(save);
    connect(enable, &QCheckBox::toggled, this, [this](bool on) {
        provider.setEnabled(on);
        status->setText(on ? "AI enabled. Refresh models; every analysis requires request review."
                           : "AI disabled. Pending requests cancelled.");
    });
    connect(refresh, &QPushButton::clicked, &provider, &OpenCodeGoProvider::refreshModels);
    connect(test, &QPushButton::clicked, this, [this] {
        status->setText(
            "Testing TLS/catalog connectivity only; this does not validate API-key authentication.");
        provider.refreshModels();
    });
    connect(cancel, &QPushButton::clicked, this, [this] {
        provider.cancel();
        status->setText("AI request cancelled.");
    });
    connect(&provider, &AIProvider::modelsChanged, this, [this] {
        const QString selected = QSettings().value("sspa/model").toString();
        models->clear();
        for (const auto& m : provider.models())
            models->addItem(m.id + " [" + apiName(m.api) + "]", m.id);
        const int position = models->findData(selected);
        models->setCurrentIndex(position >= 0 ? position : 0);
        status->setText(
            QString("%1 models discovered. Unsupported API mappings cannot send.").arg(models->count()));
    });
    connect(models, &QComboBox::activated, this,
        [this] { QSettings().setValue("sspa/model", models->currentData()); });
    connect(&provider, &AIProvider::failed, this,
        [this](const QString& problem) { status->setText("AI error: " + problem); });
    connect(&provider, &AIProvider::completed, this, [this](QJsonObject result, QJsonObject metadata) {
        lastResult = { { "result", result }, { "metadata", metadata } };
        output->setPlainText(QString::fromUtf8(QJsonDocument(lastResult).toJson()));
        status->setText(
            result.value("classification").toString() + " — separate from deterministic findings");
        evidence->clear();
        QSet<int> frames;
        for (const auto& o : result.value("observations").toArray())
            for (const auto& n : o.toObject().value("evidence_frames").toArray())
                frames.insert(n.toInt());
        auto sorted = frames.values();
        std::sort(sorted.begin(), sorted.end());
        for (int f : sorted) {
            auto* item = new QListWidgetItem(QString("Go to evidence frame %1").arg(f), evidence);
            item->setData(Qt::UserRole, f);
        }
    });
    connect(evidence, &QListWidget::itemActivated, this,
        [this](QListWidgetItem* item) { emit navigate(item->data(Qt::UserRole).toUInt()); });
    connect(save, &QPushButton::clicked, this, [this] {
        if (lastResult.empty())
            return;
        const auto path = QFileDialog::getSaveFileName(this, "Export AI result", {}, "JSON (*.json)");
        if (path.isEmpty())
            return;
        QSaveFile f(path);
        if (!f.open(QIODevice::WriteOnly) || f.write(QJsonDocument(lastResult).toJson()) < 0 || !f.commit())
            status->setText("AI export failed");
    });
}
void AiPanel::invalidate()
{
    ++contextGeneration;
    provider.cancel();
    output->clear();
    evidence->clear();
    lastResult = {};
    status->setText("Capture state changed. Previous AI context invalidated.");
}
void AiPanel::analyze(SanitizedContext context, QString classification)
{
    if (!provider.enabled()) {
        status->setText("Enable AI Explanation / Analysis to prepare a remote request. Local analysis "
                        "remains available.");
        return;
    }
    Model model;
    for (const auto& m : provider.models())
        if (m.id == models->currentData().toString())
            model = m;
    auto request = prepareRequest(
        model, std::move(context), question->text(), classification, maxBytes->value(), maxTokens->value());
    if (!request.error.isEmpty()) {
        status->setText(request.error);
        return;
    }
    const auto epoch = contextGeneration;
    QDialog preview(this);
    preview.setWindowTitle("View AI Request — exact outbound JSON");
    preview.resize(850, 650);
    auto* layout = new QVBoxLayout(&preview);
    auto* label = new QLabel("Destination: " + request.url.toString()
            + "\nOnly this JSON body will be sent. Authentication is a separate HTTPS header.",
        &preview);
    label->setTextFormat(Qt::PlainText);
    label->setWordWrap(true);
    layout->addWidget(label);
    auto* text = new QPlainTextEdit(&preview);
    text->setReadOnly(true);
    text->setPlainText(QString::fromUtf8(request.body));
    layout->addWidget(text);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, &preview);
    auto* send = buttons->addButton("Send", QDialogButtonBox::AcceptRole);
    send->setObjectName("sendAiRequest");
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &preview, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &preview, &QDialog::reject);
    // A capture reset or disabling AI while this nested dialog is open invalidates its prepared body.
    const auto invalidation = connect(&provider, &AIProvider::destroyed, &preview, &QDialog::reject);
    connect(enable, &QCheckBox::toggled, &preview, [&preview](bool on) {
        if (!on)
            preview.reject();
    });
    if (preview.exec() == QDialog::Accepted && epoch == contextGeneration) {
        status->setText("AI request in progress; deterministic analysis continues.");
        provider.send(request);
    }
    disconnect(invalidation);
}
}
