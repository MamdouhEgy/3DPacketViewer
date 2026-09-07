# Version gate investigation

Investigation date: 2026-09-07. This is an investigation record, not a completed validation claim.

Pinned upstream: Wireshark development 4.7.4, commit
`9fc76ca769c9226b3d484cc43e5b62289fab1da3`, fetched from
https://gitlab.com/wireshark/wireshark (HEAD at investigation time).

Environment: Ubuntu 24.04.4 LTS, x86_64, Linux 7.0.0-31-generic;
GCC/G++ 13.3.0; CMake 3.28.3; Ninja 1.11.1; Qt 6.4.2.
The upstream source requires Qt >= 6.2 on Linux; Windows and macOS
checks require >= 6.5.3. System development packages were unavailable;
sudo required a password. Ubuntu development packages were downloaded and
extracted into a temporary local prefix without modifying system directories.

## Primary sources inspected

- https://www.wireshark.org/docs/wsdg_html/
- https://www.wireshark.org/docs/wsar_html/uiqt__plugin_8h.html
- https://www.wireshark.org/docs/wsar_html/class_packet_diagram.html
- https://www.wireshark.org/docs/wsar_html/class_proto_tree.html
- https://www.wireshark.org/docs/wsar_html/structfield__info.html
- https://www.wireshark.org/docs/wsar_html/proto_8h_source.html
- https://www.wireshark.org/docs/wsar_html/plugin__if_8h_source.html

The published API pages describe 4.7.3, whereas fetched source reports 4.7.4.
Implementation decisions must therefore use the pinned source.

## Findings from pinned source

`ui/plugins/include/uiqt_plugin.h` registers a Qt UI module callback.
`plugins/ui/pluginifdemo` demonstrates generated registration, a MODULE
linked against epan and uiqt_plugin, and modeless Qt dialogs. The example
is opt-in (`ENABLE_PLUGIN_IFDEMO`). Its menu callback receives a generated
UI form pointer, **not a QWidget**; blindly casting it is invalid.

`plugin_if_get_capture_file` invokes the extraction callback synchronously
from `ui/qt/wireshark_main_window.cpp`. Its capture exposes `current_frame`,
`edt`, and `finfo_selected`. It does not supply a packet-change subscription
or a field-selection setter.

`PacketDiagram::connectToMainWindow` connects MainWindow's public
`setCaptureFile`, `framesSelected(QList<int>)`, and
`fieldSelected(FieldInformation*)` signals. `selectedFrameChanged` requires
exactly one selected frame and an EDT/tree, otherwise clearing its contents.
`PacketList` emits framesSelected after `cf_select_packet` invalidates the
previous dissection. Capture removal clears PacketDiagram's scene.
Field selection is forwarded bidirectionally through FieldInformation.
MainWindow and FieldInformation are executable-owned Qt classes without
WS_DLL_PUBLIC exports; a plugin must not assume portable binary linkage to
their methods. Public Qt meta-object signals can be connected without linking
the executable's C++ symbols. No docking operation appears in plugin_if.

`plugins/CMakeLists.txt` supports CUSTOM_PLUGIN_SRC_DIR with add_subdirectory.
The source/build integration path can use a plugin source link and this
configuration variable, without editing upstream implementation files.
The installed uiqt headers alone do not include the capture/dissection and
Qt integration environment of pluginifdemo. An installed-SDK out-of-tree
build has not yet been validated.

`epan/proto.h` defines unsigned start/length, appendix ranges, ds_tvb,
flags, hfinfo bitmask, proto_layer_num and total_layer_num. FI_BITS_SIZE=0
explicitly means length*8. In proto.c, new_field_info adds tvb_raw_offset
to start and assigns tvb_get_ds_tvb; offsets already refer to that source.
Mask bit-size records the bounding span, not popcount: non-contiguous masks
must be resolved independently. FI_BITS_OFFSET derives from the registered
container width for masked fields. Byte order must be considered when mapping
a numeric mask to MSB-first wire coordinates. A raw offset of zero does not
prove that an arbitrary data source is the original frame.

Wireshark's COPYING and the inspected UI-plugin files use GPL-2.0-or-later.
The project will use the same license for Wireshark-linked code.

Confirmed dissector identifiers from proto_register_protocol calls:
mbtcp, modbus, iec60870_104, iec60870_asdu, goose, mms, sv, dnp3.
Their presence is not evidence that project fixture tests have passed.

## Executed baseline gate

PASS: clean configure and complete unmodified build, including Wireshark,
tshark, text2pcap and default plugins. Final command: cmake --build with
Ninja, 12 parallel jobs, RelWithDebInfo. The source git status was empty.
PASS: launched the baseline Qt GUI using xcb, observed its visible window,
and inspected a window capture displaying 4.7.4 (9fc76ca769c9).
Implementation began only after this gate passed.

Chosen integration: source-linked custom plugin using upstream CMake extension;
modeless QWidget owned by the main window; QObject public signal connections
plus synchronous plugin_if capture callbacks. No upstream adapter patch.
Reverse native field selection is unavailable through the exported interface;
the plugin's inspector and source-specific byte highlighting are authoritative.
