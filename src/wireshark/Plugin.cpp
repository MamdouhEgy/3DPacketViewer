// SPDX-License-Identifier: GPL-2.0-or-later
#include <config.h>
#include <epan/proto.h>
#include <ui/plugins/include/plugin_if.h>
#include <QApplication>
#include <QPointer>
#include "WiresharkAdapter.h"
#ifdef PACKETVIEWER_GUI_TESTS
#include "tests/integration/GuiTests.h"
#include <QTimer>
#include <QAction>
#endif
static QPointer<pv::PacketViewerWidget> viewer;
static void openViewer(ext_menubar_gui_type gui, void*, void*)
{
    if (gui != EXT_MENUBAR_QT_GUI)
        return;
    if (!viewer) {
        QWidget* host = nullptr;
        for (auto* w : QApplication::topLevelWidgets())
            if (w->inherits("WiresharkMainWindow")) {
                host = w;
                break;
            }
        if (!host)
            return;
        viewer = new pv::PacketViewerWidget(host);
        new pv::WiresharkAdapter(host, viewer);
    }
    viewer->show();
    viewer->raise();
    viewer->activateWindow();
}
extern "C" void uiqt_register_3dpacketviewer(void);
extern "C" void uiqt_register_3dpacketviewer(void)
{
    const int protocol = proto_register_protocol("3D Packet Viewer UI", "3DPacketViewer", "packetviewer3d");
    auto* menu = ext_menubar_register_menu(protocol, "3DPacketViewer", true);
    ext_menubar_set_parentmenu(menu, "Tools");
    ext_menubar_add_entry(
        menu, "Open 3D packet viewer", "Inspect the selected Wireshark packet", openViewer, nullptr);
#ifdef PACKETVIEWER_GUI_TESTS
    if (qEnvironmentVariableIsSet("PACKETVIEWER_TEST_DIR"))
        QTimer::singleShot(2500, qApp, [] {
            for (auto* window : QApplication::topLevelWidgets()) {
                if (!window->inherits("WiresharkMainWindow"))
                    continue;
                for (auto* action : window->findChildren<QAction*>()) {
                    if (action->text() == "Open 3D packet viewer") {
                        action->trigger();
                        break;
                    }
                }
            }
            if (viewer)
                runPacketViewerGuiTests(viewer, viewer->parentWidget());
        });
#endif
}
