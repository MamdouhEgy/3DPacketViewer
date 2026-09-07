// SPDX-License-Identifier: GPL-2.0-or-later
#include "PacketViewerWidget.h"
#include <QToolBar>
#include <QVBoxLayout>
#include <QSplitter>
#include <QDoubleSpinBox>
#include <QTimer>
#include <QSignalBlocker>
namespace pv
{
PacketViewerWidget::PacketViewerWidget(QWidget* parent)
    : QWidget(parent, Qt::Window)
{
    setWindowTitle("3DPacketViewer");
    setObjectName("3DPacketViewer");
    resize(1250, 900);
    auto* layout = new QVBoxLayout(this);
    auto* toolbar = new QToolBar(this);
    layout->addWidget(toolbar);
    renderer = new PacketRenderer(this);
    renderer->setObjectName("packetViewport");
    auto action = [&](QString title, QString key, auto callback, bool check = false) {
        auto* a = toolbar->addAction(title);
        a->setShortcut(QKeySequence(key));
        a->setShortcutContext(Qt::WidgetWithChildrenShortcut);
        addAction(a);
        a->setCheckable(check);
        connect(a, &QAction::triggered, this, callback);
        return a;
    };
    action("Reset", "R", [this] {
        renderer->camera.reset();
        renderer->fitAll();
    });
    action("Fit packet", "F", [this] { renderer->fitAll(); });
    action("Fit field", "", [this] { renderer->fitSelected(); });
    auto* explode = action(
        "Explode", "E",
        [this](bool b) {
            renderer->layout.exploded = b;
            renderer->rebuild();
        },
        true);
    explode->setChecked(true);
    action(
        "Orthographic", "O",
        [this](bool b) {
            renderer->camera.orthographic = b;
            renderer->update();
        },
        true);
    auto* labels = action(
        "Labels", "L",
        [this](bool b) {
            renderer->labels = b;
            renderer->update();
        },
        true);
    labels->setChecked(true);
    auto* generated = action(
        "Generated", "G",
        [this](bool b) {
            showGenerated = b;
            filterGenerated();
        },
        true);
    generated->setChecked(true);
    action("Clear selection", "Escape", [this] { selectField(-1); });
    auto* mode = new QComboBox(toolbar);
    mode->addItems({ "Protocol stack", "Wire field view" });
    toolbar->addWidget(mode);
    connect(mode, &QComboBox::currentIndexChanged, this, [this](int i) {
        renderer->layout.wireView = i == 1;
        renderer->rebuild(true);
    });
    auto* row = new QComboBox(toolbar);
    row->addItems({ "32 bits/row", "64 bits/row", "128 bits/row" });
    row->setCurrentIndex(1);
    toolbar->addWidget(row);
    connect(row, &QComboBox::currentIndexChanged, this, [this](int i) {
        renderer->layout.rowBits = 32 << i;
        renderer->rebuild(true);
    });
    auto* spacing = new QDoubleSpinBox(toolbar);
    spacing->setPrefix("Spacing ");
    spacing->setRange(.2, 20);
    spacing->setValue(3);
    toolbar->addWidget(spacing);
    connect(spacing, &QDoubleSpinBox::valueChanged, this, [this](double v) {
        renderer->layout.spacing = float(v);
        renderer->rebuild();
    });
    status = new QLabel(this);
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    layout->addWidget(status);
    auto* split = new QSplitter(this);
    layout->addWidget(split, 1);
    split->addWidget(renderer);
    auto* details = new QSplitter(Qt::Vertical, split);
    tree = new QTreeWidget(details);
    tree->setHeaderLabels({ "Wireshark protocol tree" });
    tree->setColumnCount(1);
    tree->setUniformRowHeights(true);
    inspector = new FieldInspector(details);
    split->addWidget(details);
    split->setSizes({ 850, 400 });
    sources = new QComboBox(this);
    layout->addWidget(sources);
    bytes = new RawByteView(this);
    layout->addWidget(bytes);
    auto* legend = new QLabel("Legend: categorical protocol colors · white = selected · gray = unmapped wire "
                              "region · [G] generated (tree only) · [D] separate data source · [H] hidden · "
                              "structural parents/aliases selectable in tree",
        this);
    legend->setWordWrap(true);
    layout->addWidget(legend);
    connect(renderer, &PacketRenderer::fieldClicked, this, &PacketViewerWidget::selectField);
    connect(renderer, &PacketRenderer::statusChanged, this, &PacketViewerWidget::updateStatus);
    connect(tree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item) {
        if (item)
            selectField(item->data(0, Qt::UserRole).toInt());
    });
    connect(sources, &QComboBox::currentIndexChanged, this, [this](int i) {
        renderer->layout.source = i;
        renderer->rebuild(true);
        bytes->setData(model, i, renderer->selected);
    });
    QTimer::singleShot(1500, this, [this] {
        if (!renderer->isValid()) {
            renderer->glError
                = "OpenGL context could not be created. Field inspector and bytes remain available.";
            updateStatus();
        }
    });
    showDiagnostic("No capture loaded.");
}
void PacketViewerWidget::setPacket(Packet p)
{
    model = std::move(p);
    QSignalBlocker treeBlock(tree), sourceBlock(sources);
    tree->clear();
    items.clear();
    sources->clear();
    if (model) {
        for (const auto& s : model->sources)
            sources->addItem(s.name + " — " + s.provenance);
        items.reserve(model->fields.size());
        for (const auto& f : model->fields) {
            auto* item = new QTreeWidgetItem();
            item->setText(0,
                QString(f.generated ? "[G] "
                        : f.derived ? "[D] "
                                    : "")
                    + (f.hidden ? "[H] " : "") + f.display);
            item->setData(0, Qt::UserRole, f.id);
            if (f.parent >= 0)
                items[f.parent]->addChild(item);
            else
                tree->addTopLevelItem(item);
            items.push_back(item);
        }
    }
    renderer->layout.source = 0;
    renderer->setPacket(model);
    filterGenerated();
    bytes->setData(model, 0, -1);
    inspector->setPlainText("Select a field in the scene or protocol tree.");
    updateStatus();
}
void PacketViewerWidget::showDiagnostic(QString text)
{
    auto m = std::make_shared<PacketModel>();
    m->diagnostic = std::move(text);
    setPacket(m);
}
void PacketViewerWidget::selectField(int id)
{
    if (!model)
        return;
    const auto* f = model->field(id);
    renderer->setSelected(f ? id : -1);
    inspector->showField(*model, f);
    if (f && f->source >= 0 && f->source < sources->count() && sources->currentIndex() != f->source)
        sources->setCurrentIndex(f->source);
    bytes->setData(model, sources->currentIndex(), f ? id : -1);
    QSignalBlocker blocker(tree);
    if (f) {
        tree->setCurrentItem(items[id]);
        tree->scrollToItem(items[id]);
    } else
        tree->setCurrentItem(nullptr);
}
void PacketViewerWidget::filterGenerated()
{
    if (!model)
        return;
    for (int i = 0; i < items.size(); ++i)
        items[i]->setHidden(!showGenerated && model->fields[i].generated);
}
void PacketViewerWidget::updateStatus()
{
    if (!model)
        return;
    status->setText(
        QString("Frame %1 · Captured %2 / reported %3 bytes · Link type %4\n%5\nExtract+model %6 ms · "
                "Geometry %7 ms · GPU upload %8 ms · First paint %9 ms · %10 objects\n%11 %12")
            .arg(model->frame)
            .arg(model->captured)
            .arg(model->reported)
            .arg(model->linkType)
            .arg(model->protocols)
            .arg(model->extractionMs, 0, 'f', 2)
            .arg(renderer->geometry.buildMs, 0, 'f', 2)
            .arg(renderer->uploadMs, 0, 'f', 2)
            .arg(renderer->firstRenderMs, 0, 'f', 2)
            .arg(renderer->geometry.tiles.size())
            .arg(model->diagnostic, renderer->glError));
}
}
