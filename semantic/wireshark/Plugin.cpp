// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include <epan/proto.h>
#include <ui/plugins/include/plugin_if.h>
#include <QApplication>
#include <QPointer>
#include "ui/Viewer.h"
#ifdef SSPA_GUI_TESTS
#include <QTimer>
#include <QAction>
void runSemanticGuiTests(sspa::Viewer*, QWidget*);
#endif
static QPointer<sspa::Viewer> semanticViewer;
static void openSemantic(ext_menubar_gui_type gui, void*, void*)
{
    if (gui != EXT_MENUBAR_QT_GUI)
        return;
    if (!semanticViewer) {
        QWidget* host = nullptr;
        for (auto* w : QApplication::topLevelWidgets())
            if (w->inherits("WiresharkMainWindow")) {
                host = w;
                break;
            }
        if (!host)
            return;
        semanticViewer = new sspa::Viewer(host);
    }
    semanticViewer->show();
    semanticViewer->raise();
    semanticViewer->activateWindow();
}
extern "C" void uiqt_register_semantic_analyzer(void);
extern "C" void uiqt_register_semantic_analyzer(void)
{
    const int id = proto_register_protocol(
        "Stateful Semantic Protocol Analyzer UI", "SemanticAnalyzer", "semantic_analyzer");
    auto* menu = ext_menubar_register_menu(id, "Stateful Semantic Protocol Analyzer", true);
    ext_menubar_set_parentmenu(menu, "Tools");
    ext_menubar_add_entry(menu, "Protocol Transactions", "Offline stateful smart-grid protocol analysis",
        openSemantic, nullptr);
#ifdef SSPA_GUI_TESTS
    if (qEnvironmentVariableIsSet("SSPA_TEST_DIR"))
        QTimer::singleShot(1800, qApp, [] {
            for (auto* host : QApplication::topLevelWidgets())
                if (host->inherits("WiresharkMainWindow")) {
                    for (auto* action : host->findChildren<QAction*>())
                        if (action->text() == "Protocol Transactions") {
                            action->trigger();
                            break;
                        }
                    if (semanticViewer)
                        runSemanticGuiTests(semanticViewer, host);
                    break;
                }
        });
#endif
}
