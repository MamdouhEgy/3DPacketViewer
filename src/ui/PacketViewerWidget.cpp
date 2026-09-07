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
    resize(1400, 950);
    auto* layout = new QVBoxLayout(this);
    auto* toolbar = new QToolBar(this);
    layout->addWidget(toolbar);
    viewMode = new QComboBox(toolbar);
    viewMode->setObjectName("viewMode");
    viewMode->addItems({ "Byte & bit map", "3D protocol stack" });
    toolbar->addWidget(viewMode);
    auto* row = new QComboBox(toolbar);
    row->addItems({ "4 bytes / row", "8 bytes / row", "16 bytes / row" });
    row->setCurrentIndex(1);
    toolbar->addWidget(row);
    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(" Emphasize protocol: ", toolbar));
    protocolFocus = new QComboBox(toolbar);
    protocolFocus->setMinimumContentsLength(14);
    toolbar->addWidget(protocolFocus);
    auto* sceneToolbar = new QToolBar(this);
    layout->addWidget(sceneToolbar);
    sceneToolbar->hide();
    renderer = new PacketRenderer(this);
    renderer->setObjectName("packetViewport");
    byteMap = new PacketByteMap(this);
    auto action = [&](QToolBar* bar, QString title, QString key, auto callback, bool check = false) {
        auto* a = bar->addAction(title);
        a->setShortcut(QKeySequence(key));
        a->setShortcutContext(Qt::WidgetWithChildrenShortcut);
        addAction(a);
        a->setCheckable(check);
        connect(a, &QAction::triggered, this, callback);
        return a;
    };
    action(toolbar, "Go to selected field", "", [this] {
        if (views->currentIndex() == 0)
            byteMap->revealSelection();
        else
            renderer->fitSelected();
    });
    auto* generated = action(
        toolbar, "Generated", "G",
        [this](bool b) {
            showGenerated = b;
            filterGenerated();
        },
        true);
    generated->setChecked(true);
    action(toolbar, "Clear selection", "Escape", [this] { selectField(-1); });
    action(sceneToolbar, "Reset", "R", [this] {
        renderer->camera.reset();
        renderer->fitAll();
    });
    action(sceneToolbar, "Fit packet", "F", [this] { renderer->fitAll(); });
    action(sceneToolbar, "Fit field", "", [this] { renderer->fitSelected(); });
    auto* explode = action(
        sceneToolbar, "Explode", "E",
        [this](bool b) {
            renderer->layout.exploded = b;
            renderer->rebuild();
        },
        true);
    explode->setChecked(true);
    action(
        sceneToolbar, "Orthographic", "O",
        [this](bool b) {
            renderer->camera.orthographic = b;
            renderer->update();
        },
        true);
    auto* labels = action(
        sceneToolbar, "Labels", "L",
        [this](bool b) {
            renderer->labels = b;
            renderer->update();
        },
        true);
    labels->setChecked(true);
    auto* spacing = new QDoubleSpinBox(sceneToolbar);
    spacing->setPrefix("Spacing ");
    spacing->setRange(.2, 20);
    spacing->setValue(3);
    sceneToolbar->addWidget(spacing);
    connect(spacing, &QDoubleSpinBox::valueChanged, this, [this](double v) {
        renderer->layout.spacing = float(v);
        renderer->rebuild();
    });
    status = new QLabel(this);
    status->setTextFormat(Qt::PlainText);
    status->setWordWrap(true);
    layout->addWidget(status);
    sources = new QComboBox(this);
    layout->addWidget(sources);
    selectionSummary = new QLabel(this);
    selectionSummary->setObjectName("selectionSummary");
    selectionSummary->setTextFormat(Qt::PlainText);
    selectionSummary->setWordWrap(true);
    selectionSummary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    selectionSummary->setStyleSheet(
        "QLabel { background: #edf3fa; color: #17283f; padding: 10px; border-radius: 4px; }");
    layout->addWidget(selectionSummary);
    auto* split = new QSplitter(this);
    layout->addWidget(split, 1);
    views = new QStackedWidget(split);
    views->addWidget(byteMap);
    views->addWidget(renderer);
    auto* details = new QSplitter(Qt::Vertical, split);
    tree = new QTreeWidget(details);
    tree->setHeaderLabels({ "Protocols & fields — select to locate" });
    tree->setColumnCount(1);
    tree->setUniformRowHeights(true);
    inspector = new FieldInspector(details);
    split->addWidget(details);
    split->setSizes({ 900, 390 });
    details->setSizes({ 250, 300 });
    bytes = new RawByteView(this);
    bytes->setMaximumHeight(155);
    layout->addWidget(
        new QLabel("Selected source bytes · offsets in hex · highlighted bits are MSB first", this));
    layout->addWidget(bytes);
    auto* legend = new QLabel(
        "Map: equal width per bit · row height has no quantitative meaning · colors identify protocols · "
        "black outline + yellow bits = selection · gray = unmapped · [G] generated: no wire bits · [D] "
        "separate source. "
        "Small fields: hover or select from the tree. Bit digits appear when space permits.",
        this);
    legend->setWordWrap(true);
    layout->addWidget(legend);
    connect(viewMode, &QComboBox::currentIndexChanged, this, [this, sceneToolbar](int i) {
        views->setCurrentIndex(i);
        sceneToolbar->setVisible(i == 1);
        protocolFocus->setEnabled(i == 0);
        if (i == 1) {
            renderer->fitAll();
            QTimer::singleShot(1000, this, [this] {
                if (views->currentIndex() == 1 && !renderer->isValid()) {
                    renderer->glError
                        = "OpenGL context unavailable. The byte map and inspector remain available.";
                    updateStatus();
                }
            });
        }
        updateStatus();
    });
    connect(row, &QComboBox::currentIndexChanged, this, [this](int i) {
        byteMap->setRowBits(32 << i);
        renderer->layout.rowBits = 32 << i;
        renderer->rebuild(true);
        updateStatus();
    });
    connect(protocolFocus, &QComboBox::currentIndexChanged, this,
        [this](int) { byteMap->setProtocolFocus(protocolFocus->currentData().toInt()); });
    connect(byteMap, &PacketByteMap::fieldClicked, this, &PacketViewerWidget::selectField);
    connect(renderer, &PacketRenderer::fieldClicked, this, &PacketViewerWidget::selectField);
    connect(renderer, &PacketRenderer::statusChanged, this, &PacketViewerWidget::updateStatus);
    connect(tree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item) {
        if (item)
            selectField(item->data(0, Qt::UserRole).toInt());
    });
    connect(sources, &QComboBox::currentIndexChanged, this, [this](int i) {
        renderer->layout.source = i;
        renderer->rebuild(true);
        byteMap->setData(model, i);
        byteMap->selectField(renderer->selected);
        bytes->setData(model, i, renderer->selected);
        updateStatus();
    });
    showDiagnostic("No capture loaded.");
}
void PacketViewerWidget::setPacket(Packet p)
{
    model = std::move(p);
    QSignalBlocker treeBlock(tree), sourceBlock(sources), focusBlock(protocolFocus);
    tree->clear();
    items.clear();
    sources->clear();
    protocolFocus->clear();
    protocolFocus->addItem("All protocols", -1);
    if (model) {
        for (const auto& s : model->sources)
            sources->addItem((s.currentFrame ? "Captured frame: " : "Separate data source: ") + s.name + " — "
                + s.provenance);
        items.reserve(model->fields.size());
        for (const auto& f : model->fields) {
            if (f.protocolGroup && f.abbreviation != "frame")
                protocolFocus->addItem(f.name, f.id);
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
    byteMap->setData(model, 0);
    byteMap->setProtocolFocus(-1);
    tree->expandToDepth(0);
    filterGenerated();
    bytes->setData(model, 0, -1);
    selectField(-1);
    inspector->setPlainText("Select a field in the map or protocol tree for complete Wireshark metadata.");
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
    byteMap->selectField(f ? id : -1);
    bytes->setData(model, sources->currentIndex(), f ? id : -1);
    if (f) {
        uint64_t bits = 0;
        for (auto range : f->ranges)
            bits += range.length;
        const QString location = f->generated ? "Generated by Wireshark — no direct wire range."
            : f->ranges.empty()
            ? "Exact bit mapping unavailable. " + f->rangeNote
            : QString("Source byte offset %1 (0x%2), byte-container length %3 · %4 represented bits%5")
                  .arg(f->start)
                  .arg(f->start, 0, 16)
                  .arg(f->length)
                  .arg(bits)
                  .arg(f->derived ? " · separate source, not current-frame bytes" : "");
        selectionSummary->setText(f->name + " · " + f->abbreviation + " · " + f->protocol + "\n"
            + f->display.left(400) + "\n" + location
            + (f->description.isEmpty() ? "" : "\n" + f->description.left(300)));
    } else {
        selectionSummary->setText(
            "Where is this value encoded? Select a field in the map or protocol tree.\n"
            "Read its decoded value here, its location in the map, and its exact bytes below. "
            "Choose a protocol to emphasize its fields, or switch to 3D to explore encapsulation.");
    }
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
    QString text = model->frame == 0 ? model->diagnostic
                                     : QString("Frame %1 · %2 captured / %3 reported bytes · %4")
                                           .arg(model->frame)
                                           .arg(model->captured)
                                           .arg(model->reported)
                                           .arg(model->protocols);
    if (model->frame && !model->diagnostic.isEmpty())
        text += "\n" + model->diagnostic;
    if (!byteMap->diagnostic().isEmpty())
        text += "\n" + byteMap->diagnostic();
    if (views->currentIndex() == 1 && !renderer->glError.isEmpty())
        text += "\n" + renderer->glError;
    status->setText(text);
    status->setToolTip(QString(
        "Extraction/model %1 ms · 3D geometry %2 ms · GPU upload %3 ms · First paint %4 ms · %5 objects")
                           .arg(model->extractionMs, 0, 'f', 2)
                           .arg(renderer->geometry.buildMs, 0, 'f', 2)
                           .arg(renderer->uploadMs, 0, 'f', 2)
                           .arg(renderer->firstRenderMs, 0, 'f', 2)
                           .arg(renderer->geometry.tiles.size()));
}
}
