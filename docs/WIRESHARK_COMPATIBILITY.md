# Wireshark compatibility

| Item | Executed target |
|---|---|
| Wireshark | 4.7.4 development |
| Commit | `9fc76ca769c9226b3d484cc43e5b62289fab1da3` |
| Qt | 6.4.2, desktop xcb |
| Compiler | GCC/G++ 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) |
| CMake | 3.28.3 |
| Ninja | 1.11.1 |
| OS | Ubuntu 24.04.4 LTS, x86_64 |
| Kernel | Linux 7.0.0-31-generic |
| Configurations | RelWithDebInfo; separate Debug with ENABLE_ASAN and ENABLE_UBSAN |
| Renderer | QOpenGLWidget, desktop OpenGL >=2.1, GLSL 1.20 |
| Development module | `run/plugins/wireshark/4.7/ui/packetviewer3d.so` |
| Installation | Upstream versioned library plugin directory, `wireshark/plugins/4.7/ui` |
| Source modification | Only a custom-plugin source link; no upstream code patch |

The unmodified target was configured, fully built, launched and visually
verified before implementation. The project's revision pin is stricter than
Wireshark's binary-plugin major/minor checks. The runtime signal connection
checks report an incompatible interface if required Qt signals are missing.

The installed SDK's UI-plugin headers do not alone establish a clean independent
Qt UI-plugin SDK with all capture and executable signal integration. The
validated build therefore uses the same source/build environment as current
pluginifdemo, through the official CUSTOM_PLUGIN_SRC_DIR extension. The
repository remains independent and does not contain the Wireshark source tree.

Wireshark exports epan and uiqt_plugin, but does not export MainWindow or
FieldInformation as a stable DLL API. Qt meta-object connections use public
signals already used by PacketDiagram. Reverse selection cannot safely create
Wireshark's native FieldInformation wrapper through the exported plugin API;
it remains confined to the viewer's own inspector and bytes.

Not tested: other Wireshark revisions, Windows, macOS, ARM, live capture,
remote X servers, and every OpenGL driver. No binary compatibility promise is
made outside the recorded target.

Licensing: the pinned Wireshark COPYING file and UI-plugin API/example carry
GPL-2.0-or-later. This project uses GPL-2.0-or-later, preserving compatibility
with the linked/integrated host. PacketDiagram and pluginifdemo were examined
as architectural references; their implementation files were not copied.
The license text is included verbatim in LICENSE.
