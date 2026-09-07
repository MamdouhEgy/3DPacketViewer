# Architecture

The native module links EPAN, uiqt_plugin, and Qt Widgets/OpenGL. It uses
Wireshark's custom source-plugin extension. The core has no Wireshark includes
or transient dissection pointers. No upstream implementation patch is required.

| Module | Responsibility |
|---|---|
| WiresharkAdapter | Public Qt frame/capture signals and synchronous plugin_if callbacks; snapshot replacement and native selection observation |
| ProtoTreeExtractor | Bounded iterative tree traversal; copies field metadata, safe semantic representations, source bytes and identities |
| PacketModel | Shared immutable snapshot with local node IDs, parents, source IDs and capture generation |
| FieldRangeResolver | Bounds checks, masks, byte order, explicit bit spans, generated-field exclusion |
| PacketGeometryEngine | Deterministic source-bit partition and wrapped shallow-box layout |
| PacketRenderer | OpenGL shader/buffer/context ownership, bounded labels, scene drawing and input dispatch |
| CameraController | Normalized quaternion rotation, center, distance, projection and scale limits |
| SelectionController | Unprojected ray and slab intersection against actual geometry boxes |
| PacketViewerWidget | Modeless window, toolbar, hierarchy, controls and diagnostics |
| FieldInspector | Plain-text exact metadata and range explanation |
| RawByteView | Virtualized source bytes, hex and MSB-first bit highlighting |
| Validation executables | Same extractor and geometry operating after EDT destruction; synthetic capture oracle and GUI driver |

## Integration and lifetime

Registration follows the current pluginifdemo build and UI registration pattern,
without copying its implementation. The menu callback's opaque GUI argument is
not a QWidget. The adapter identifies the top-level WiresharkMainWindow through
public QObject metadata and subscribes to its documented signals by signature.
This avoids linking against non-exported executable C++ symbols. The window has
a Wireshark QWidget parent and the Qt::Window flag; docking is not exposed by
the public plugin interface.

Frame signals arrive after Wireshark selects/dissects the frame. On the GUI
thread, plugin_if_get_capture_file invokes the extraction callback synchronously.
No capture_file, EDT, field_info, proto_node, or tvbuff pointer leaves that
callback in application state. PacketModel uses only value types. The renderer
holds shared_ptr<const PacketModel>. On each frame change it replaces the
snapshot, geometry, selection and source view. Multiple/empty selection clears
the viewer. Capture changes invalidate state before requesting a fresh callback.

Native field signals schedule a zero-delay update **without copying the signal's
FieldInformation pointer**. A fresh callback traverses only the current tree,
compares the current selected live field, and maps its traversal position to a
local copied ID. This is one-way synchronization: public plugin_if supplies no
setter, and FieldInformation's executable-owned C++ methods are not an exported
plugin ABI. Clicks inside the viewer update its own inspector and byte view.

All dissection access, extraction and Qt operations are on the GUI thread.
The implementation does not redisect packets or poll the capture on a timer.
Geometry construction runs on copied data. GPU resources are created/uploaded
with the QOpenGLWidget context current and destroyed on context teardown;
shaders are compiled once per context. One transparent QWidget overlay paints
labels and selection outlines through Qt, independently of driver-specific
OpenGL paint-engine text behavior; there is no widget per field. A shader/context failure is visible in
the surrounding widget while the inspector remains available.

## Provenance and layout

Wireshark stores source-relative offsets in field_info; the extractor does not
add tvb offsets a second time. Data-source identity is compared while pointers
are valid, then replaced by a local index. Current-frame identity is established
against the EDT's original data source. Other buffers are separately named,
copied and rendered; zero offset does not imply original-frame provenance.
No mapping across reassembly, decryption or decompression is invented.

The geometry sweep resolves overlapping intervals globally within one source.
Later protocol-node interpretations win, then greater tree depth, then earlier
local tree ID. This ensures application fields take precedence over a transport
payload convenience field. Structural fields only cover portions left by more
specific winning interpretations; there is never additive parent/child area.
All original interpretations remain in the hierarchy/inspector.

Each winning span splits at configurable row boundaries. X is MSB-first bit
position modulo row width; Y is negative row number times a fixed presentation
pitch. Layer number affects only Z in stack mode; wire mode sets all layers to
zero. Rendering never changes the source bytes, semantic values or bit spans.

## Untrusted input and resource limits

Source bytes are limited to 64 MiB per snapshot; copied field text to 32 MiB;
trees to 100000 nodes; geometry to 200000 tiles. Exceeding a limit produces an
explicit diagnostic and omits remaining content. Raw semantic string/byte
values exceeding 4096 bytes are not expanded into text; their copied source
bytes remain inspectable. Tree traversal is iterative. Byte rendering is
virtualized. Geometry arithmetic uses 64-bit ranges with subtraction-based
bounds checks. Raw input never becomes shader code, commands or HTML. Tooltip
text is HTML-escaped; inspector text is plain text. Labels are limited to 100
field labels and 32 protocol labels per paint. No packet-dependent network
operation exists in the runtime.
