// SPDX-License-Identifier: GPL-2.0-or-later
#include "Viewer.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QSplitter>
#include <QTabWidget>
#include <QTableView>
#include <QHeaderView>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QLineEdit>
#include <QFileDialog>
#include <QSaveFile>
#include <QJsonDocument>
namespace sspa
{
Viewer::Viewer(QWidget* host)
    : QWidget(host, Qt::Window)
    , adapter(host, this)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle("Stateful Semantic Protocol Analyzer — Protocol Transactions");
    resize(1400, 900);
    setObjectName("semanticViewer");
    auto* layout = new QVBoxLayout(this);
    auto* controls = new QHBoxLayout;
    layout->addLayout(controls);
    auto button = [&](const QString& title, auto action) {
        auto* b = new QPushButton(title, this);
        controls->addWidget(b);
        connect(b, &QPushButton::clicked, this, action);
        return b;
    };
    button("Rebuild analysis", [this] { adapter.retap(); });
    button("Load asset / topology policy…", [this] {
        const auto path = QFileDialog::getOpenFileName(this, "Asset policy", {}, "JSON (*.json)");
        if (path.isEmpty())
            return;
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly) || f.size() > 1048576) {
            status->setText("Policy file unavailable or too large");
            return;
        }
        QJsonParseError parse;
        auto doc = QJsonDocument::fromJson(f.readAll(), &parse);
        QString error;
        auto policy = Policy::parse(doc.object(), error);
        if (parse.error != QJsonParseError::NoError || !doc.isObject() || !policy) {
            status->setText("Invalid policy: " + error);
            return;
        }
        adapter.engine.policy = *policy;
        adapter.retap();
    });
    button("Export deterministic analysis…", [this] {
        auto path = QFileDialog::getSaveFileName(this, "Local deterministic report", {}, "JSON (*.json)");
        if (path.isEmpty())
            return;
        QSaveFile f(path);
        if (!f.open(QIODevice::WriteOnly)
            || f.write(QJsonDocument(localReport(adapter.engine, adapter.captureBoundary)).toJson()) < 0
            || !f.commit())
            status->setText("Export failed");
    });
    button("Go to first contributing frame", [this] {
        if (!navigationFrames.empty())
            Adapter::navigate(navigationFrames.front());
    });
    button("Show contributing packets", [this] { Adapter::filter(navigationFrames); });
    status = new QLabel(this);
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    layout->addWidget(status);
    auto* split = new QSplitter(Qt::Horizontal, this);
    layout->addWidget(split, 1);
    auto* left = new QSplitter(Qt::Vertical, split);
    auto* tabs = new QTabWidget(left);
    auto table = [&](SemanticTable::Kind kind, SemanticTable*& model, const QString& name) {
        auto* t = new QTableView(tabs);
        model = new SemanticTable(adapter.engine, kind, t);
        t->setModel(model);
        t->setSelectionBehavior(QAbstractItemView::SelectRows);
        t->setSelectionMode(QAbstractItemView::ExtendedSelection);
        t->setAlternatingRowColors(true);
        t->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        t->horizontalHeader()->setDefaultSectionSize(140);
        t->verticalHeader()->hide();
        tabs->addTab(t, name);
        return t;
    };
    transactions = table(SemanticTable::Transactions, transactionModel, "Protocol Transactions");
    transactions->setObjectName("semanticTransactions");
    events = table(SemanticTable::Events, eventModel, "Semantic Timeline / Events");
    events->setObjectName("semanticEvents");
    findings = table(SemanticTable::Findings, findingModel, "Deterministic Findings");
    connect(transactions, &QTableView::clicked, this, [this](QModelIndex i) { showTransaction(i.row()); });
    connect(events, &QTableView::clicked, this, [this](QModelIndex i) { showEvent(i.row()); });
    connect(findings, &QTableView::clicked, this, [this](QModelIndex i) { showFinding(i.row()); });
    connect(events, &QTableView::doubleClicked, this,
        [this](QModelIndex i) { Adapter::navigate(adapter.engine.events[i.row()].frame); });
    connect(transactions, &QTableView::doubleClicked, this, [this](QModelIndex i) {
        showTransaction(i.row());
        if (!navigationFrames.empty())
            Adapter::navigate(navigationFrames.front());
    });
    details = new QPlainTextEdit(left);
    details->setReadOnly(true);
    details->setPlaceholderText("Select an event, transaction or deterministic finding to inspect exact "
                                "values, provenance and state transitions.");
    auto* right = new QTabWidget(split);
    auto* contexts = new QWidget(right);
    right->addTab(contexts, "Semantic Context / Differences");
    auto* contextLayout = new QVBoxLayout(contexts);
    auto* form = new QFormLayout;
    contextLayout->addLayout(form);
    mode = new QComboBox(contexts);
    mode->addItems({ "Current finding", "Selected transactions", "Selected packets / events",
        "Current conversation", "Current publisher", "Current protocol", "Time window around selected packet",
        "Frame range", "Capture summary", "Current device", "Compare two ranges", "Compare conversations",
        "Compare publishers", "Compare devices", "Compare transactions" });
    mode->setCurrentIndex(2);
    mode->setObjectName("semanticContextMode");
    form->addRow("Context", mode);
    auto spin = [&](const QString& name, int value) {
        auto* s = new QSpinBox(contexts);
        s->setRange(1, 2147483647);
        s->setValue(value);
        form->addRow(name, s);
        return s;
    };
    first = spin("Baseline / range first frame", 1);
    last = spin("Baseline / range last frame", 1000);
    first->setObjectName("semanticFirstFrame");
    last->setObjectName("semanticLastFrame");
    otherFirst = spin("Comparison first frame", 1001);
    otherLast = spin("Comparison last frame", 2000);
    before = new QDoubleSpinBox(contexts);
    before->setRange(0, 1800);
    before->setValue(5);
    form->addRow("Seconds before", before);
    after = new QDoubleSpinBox(contexts);
    after->setRange(0, 1800);
    after->setValue(5);
    form->addRow("Seconds after", after);
    compareIdentity = new QLineEdit(contexts);
    form->addRow("Other flow / publisher / device / transaction ID", compareIdentity);
    maxEvents = spin("Maximum representative events", 500);
    maxEvents->setMaximum(5000);
    auto* local = new QPushButton("Analyze Semantic Differences (local)", contexts);
    contextLayout->addWidget(local);
    auto* analyze = new QPushButton("Analyze Differences with AI / View AI Request", contexts);
    contextLayout->addWidget(analyze);
    auto* explain = new QPushButton("Explain Current Finding with AI / View AI Request", contexts);
    contextLayout->addWidget(explain);
    contextView = new QPlainTextEdit(contexts);
    contextView->setReadOnly(true);
    contextView->setObjectName("semanticContext");
    contextLayout->addWidget(contextView, 1);
    auto* note = new QLabel("Statistics and comparisons are computed locally. Endpoint and dataset names in "
                            "the remote representation are pseudonyms. Numeric IOAs and semantic "
                            "measurements remain visible in the preview.",
        contexts);
    note->setWordWrap(true);
    contextLayout->addWidget(note);
    ai = new AiPanel(right);
    right->addTab(ai, "Optional AI Settings / Results");
    connect(ai, &AiPanel::navigate, this, [](quint32 f) { Adapter::navigate(f); });
    connect(local, &QPushButton::clicked, this, [this] { makeContext(); });
    connect(analyze, &QPushButton::clicked, this, [this] { ai->analyze(makeContext()); });
    connect(explain, &QPushButton::clicked, this, [this] {
        mode->setCurrentIndex(0);
        ai->analyze(makeContext(), "AI_GENERATED_EXPLANATION");
    });
    connect(&adapter, &Adapter::updated, this, &Viewer::refresh);
    connect(&adapter, &Adapter::invalidated, this, [this] {
        ai->invalidate();
        details->clear();
        contextView->clear();
        navigationFrames.clear();
        refresh();
    });
    connect(&adapter, &Adapter::selectionChanged, this, [this] {
        const auto list = adapter.selectedFrames;
        if (list.size() == 1) {
            const auto ids = adapter.engine.byFrame.value(list.front());
            if (!ids.empty()) {
                events->selectRow(ids.front());
                events->scrollTo(eventModel->index(ids.front(), 0));
                showEvent(ids.front());
            }
        } else
            events->clearSelection();
    });
    split->setSizes({ 850, 550 });
    left->setSizes({ 550, 220 });
    refresh();
}
void Viewer::refresh()
{
    transactionModel->boundary = adapter.captureBoundary;
    transactionModel->refresh();
    eventModel->refresh();
    findingModel->refresh();
    status->setText(
        QString("%1 semantic events · %2 transactions · %3 deterministic findings · frame watermark %4. %5")
            .arg(adapter.engine.events.size())
            .arg(adapter.engine.transactions.size())
            .arg(adapter.engine.findings.size())
            .arg(adapter.engine.lastFrame)
            .arg(adapter.engine.diagnostic));
}
void Viewer::showTransaction(int i)
{
    if (i < 0 || i >= adapter.engine.transactions.size())
        return;
    const auto& t = adapter.engine.transactions[i];
    navigationFrames = t.frames;
    details->setPlainText(QString::fromUtf8(QJsonDocument(localTransaction(t)).toJson()));
}
void Viewer::showEvent(int i)
{
    if (i < 0 || i >= adapter.engine.events.size())
        return;
    const auto& e = adapter.engine.events[i];
    navigationFrames = { e.frame };
    details->setPlainText(QString::fromUtf8(QJsonDocument(localEvent(e)).toJson()));
}
void Viewer::showFinding(int i)
{
    if (i < 0 || i >= adapter.engine.findings.size())
        return;
    const auto& f = adapter.engine.findings[i];
    navigationFrames = f.frames;
    details->setPlainText(QString::fromUtf8(QJsonDocument(localFinding(f)).toJson()));
}
Selector Viewer::selector(int choice, bool baseline) const
{
    Selector s;
    const auto& engine = adapter.engine;
    const Event* current = nullptr;
    if (events->currentIndex().isValid() && events->currentIndex().row() < engine.events.size())
        current = &engine.events[events->currentIndex().row()];
    if (!current && !adapter.selectedFrames.empty()) {
        const auto ids = engine.byFrame.value(adapter.selectedFrames.front());
        if (!ids.empty())
            current = &engine.events[ids.front()];
    }
    switch (choice) {
    case 0:
        if (findings->currentIndex().isValid() && findings->currentIndex().row() < engine.findings.size())
            s.finding = engine.findings[findings->currentIndex().row()].id;
        else
            s.frames.insert(0);
        break;
    case 1:
        for (const auto& row : transactions->selectionModel()->selectedRows())
            if (row.row() < engine.transactions.size())
                s.transactionIds.insert(engine.transactions[row.row()].id);
        if (s.transactionIds.empty())
            s.frames.insert(0);
        break;
    case 2:
        for (const auto& row : events->selectionModel()->selectedRows())
            if (row.row() < engine.events.size())
                s.frames.insert(engine.events[row.row()].frame);
        if (s.frames.empty())
            for (int frame : adapter.selectedFrames)
                if (frame > 0)
                    s.frames.insert(frame);
        if (s.frames.empty())
            s.frames.insert(0);
        break;
    case 3:
    case 11:
        if (current)
            s.flow = baseline ? current->flow : compareIdentity->text();
        if (s.flow.isEmpty())
            s.frames.insert(0);
        break;
    case 4:
    case 12:
        if (current)
            s.publisher = baseline ? current->publisher : compareIdentity->text();
        if (s.publisher.isEmpty())
            s.frames.insert(0);
        break;
    case 5:
        if (current)
            s.protocol = current->protocol;
        else
            s.frames.insert(0);
        break;
    case 6:
        if (current) {
            s.startMs = current->timeMs - before->value() * 1000;
            s.endMs = current->timeMs + after->value() * 1000;
        } else
            s.frames.insert(0);
        break;
    case 7:
    case 10:
        s.firstFrame = baseline ? first->value() : otherFirst->value();
        s.lastFrame = baseline ? last->value() : otherLast->value();
        if (s.firstFrame > s.lastFrame)
            s.frames.insert(0);
        break;
    case 9:
    case 13:
        if (current)
            s.device = baseline ? current->source : compareIdentity->text();
        if (s.device.isEmpty())
            s.frames.insert(0);
        break;
    case 14:
        if (baseline && transactions->currentIndex().isValid()
            && transactions->currentIndex().row() < engine.transactions.size())
            s.transaction = engine.transactions[transactions->currentIndex().row()].id;
        else if (!baseline)
            s.transaction = compareIdentity->text();
        if (s.transaction.isEmpty())
            s.frames.insert(0);
        break;
    default:
        break;
    }
    return s;
}
SanitizedContext Viewer::makeContext()
{
    ContextLimits limits;
    limits.maxEvents = maxEvents->value();
    const auto a = buildContext(adapter.engine, selector(mode->currentIndex()), limits);
    Sanitizer sanitizer;
    auto result = mode->currentIndex() >= 10
        ? sanitizer.build(
              compareContexts(a, buildContext(adapter.engine, selector(mode->currentIndex(), false), limits)))
        : sanitizer.build(a);
    contextView->setPlainText(
        result.error.isEmpty() ? QString::fromUtf8(QJsonDocument(result.json).toJson()) : result.error);
    return result;
}
}
