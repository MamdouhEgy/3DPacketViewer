# Executed validation

Date: 2026-09-07. Platform and target are recorded in WIRESHARK_COMPATIBILITY.md.
These are executed results, not proposed tests. Raw reports are in `validation/`.

| Check set | Passed | Failed | Skipped / NOT TESTED |
|---|---:|---:|---:|
| Qt Test core cases (including init/cleanup) | 25 | 0 | 0 |
| Fixture/invariant/tshark checks | 236 | 0 | 0 |
| Native in-process Wireshark GUI checks | 59 | 0 | 0 |
| Relevant upstream Wireshark tests | 55 | 0 | 11 |
| Distinct checks above | **375** | **0** | **11** |

Independent standalone configure/build and CTest: PASS (one CTest entry runs
all 25 core results). Clean integrated configure and full Wireshark build:
PASS. Module loads from the versioned UI plugin directory. Current upstream
check_apis.py: zero warnings. Project compiler warnings: none observed.
The source integration script was executed twice against the same checkout:
PASS, no additional upstream modification required.

## Byte-map redesign (0.2.0)

Executed after the redesign: fresh standalone Debug configure/build/CTest,
25 core results, rebuilt normal and fully instrumented native modules,
236 fixture checks, and 59 native GUI checks on both normal and ASan/UBSan
builds (exit 0). API checks reported zero warnings; formatting and diff checks
passed. New reports are in `validation/redesign/`; the original reports remain
as historical evidence. The full unmodified/integrated Wireshark builds and
55 upstream passes/11 skips above are retained from the initial validation;
the upstream suite was not repeated for this UI-only change.

Twelve added GUI checks cover default map visibility, actual mouse picking,
the known Modbus transaction ID/value/location, exact selected bits, protocol
emphasis without relocation, wrapping without semantic changes, generated
fields with no positions, switching to 3D, separate reassembly source selection,
one-bit flag neighbor exclusion, structural parent overlay without a tile, and
restoring the map after capture changes. The updated screenshot is a real
native rendering of the synthetic Modbus fixture. These checks establish
behavior and mapping, not measured improvements in analyst productivity.

## Fixture ground truth

There are 21 source-controlled synthetic fixtures, 23 frames, and 29 manually
established field-location assertions. `tests/fixtures/packets.json` contains
the hexadecimal source bytes and origin/scope notes. The generator must reproduce
that file exactly. Captures are generated locally and are not committed.

[Actual expected/extracted field-location table](../validation/ground-truth.md)
records protocol, abbreviation, frame, byte start/length, resolved MSB-first
bit start/length, data source, and PASS/FAIL. `[start,length]` describes each
occupied span; disjoint masks are tested separately in core tests.

The expected locations follow the known construction: Ethernet type at bytes
12–13; IPv4 begins at 14 and its version/IHL are the two header nibbles; ports
follow the explicitly constructed IP header; VLAN ID is the low 12 bits of
TCI; Modbus MBAP precedes its function byte; IEC APCI precedes ASDU. The MMS
fixture's exported-PDU header is 12 bytes and its BER invokeID value is byte 16.
Reassembled expected ranges begin within the separately constructed datagram/PDU,
not at any claimed original-frame offset. Hand-checked construction is independent
of the extractor. This remains limited test coverage, not exhaustive standards
certification.

The separate tshark PDML comparison checks original-source byte ranges for
non-generated/non-hidden fields with exported pos/size attributes. PDML's
special `data` value-only entries lack location attributes and cannot serve as
range oracles; they are not compared. PDML does not establish exact mask
occupancy or independently certify protocol correctness. Those properties use
explicit known-location and unit checks.

The same extractor frees the Wireshark EDT before validating the copied model
and constructing geometry. All original source bytes are compared against the
fixture after extraction. Canonical tiles form one contiguous, non-overlapping
partition per source; generated fields have no ranges; additional-source fields
never claim original-frame wire backing. No out-of-bounds ranges passed.

## Native GUI execution

The optional test driver is compiled into the UI plugin only with
PACKETVIEWER_GUI_TESTS=ON. It drives the actual Wireshark application, opens
captures through its public Qt slot, changes selected frames via plugin_if,
and sends Qt mouse/wheel events into the actual QOpenGLWidget. Native Packet
Details selection uses the tree's public item-selection API and mouse events;
the viewer updates through its normal adapter. No mock capture, renderer or
adapter is substituted. The actual registered menu action opens the viewer.
The GUI suite also compares label raster output and bounds idle repainting.

Passed: loading, packet model, rendered framebuffer, rotation, zoom, pan,
exploded/collapsed geometry invariant, projection, labels, generated toggle,
inspector, byte/bit highlighting, native-to-viewer field synchronization,
ray-picked field click, TCP reassembly provenance, repeated frame switching,
display-filter removal/restoration, all core and smart-grid fixtures, malformed
and truncated captures, 1080-field GOOSE, redissection, capture close invalidation,
reopen, and normal process shutdown (exit 0). Reverse native field synchronization
is NOT SUPPORTED by the exported interface; viewer-local selection is tested.

## Sanitizers and the desktop-library control experiment

A separate **full Wireshark Debug build**, including the plugin, was compiled
with ENABLE_ASAN=ON and ENABLE_UBSAN=ON. Core and all fixture checks passed with
ASAN_OPTIONS=detect_leaks=1 and UBSAN_OPTIONS=halt_on_error=1. The isolated GUI
run passed all 59 checks and exited 0 with the same sanitizer settings.
No sanitizer suppression was used.

The original desktop GUI run **failed LeakSanitizer at shutdown**: 553 bytes
in six allocations originating in QtDBus meta-object creation called by
Wireshark's readViaPortal theme detection before plugin initialization. A
control run with WIRESHARK_PLUGIN_DIR pointing at an empty directory and no
viewer reproduced the same 553 bytes/six allocations. Both unsuppressed logs
are retained. No 3DPacketViewer allocation appears in those leak stacks.

Removing the desktop DBus connection exposed an additional 56-byte GTK/ATK
accessibility startup leak in the system Qt GTK platform theme, also outside
the plugin; its unsuppressed report is retained. The final isolated test session
uses no session bus, Qt Fusion style, and NO_AT_BRIDGE=1. These settings avoid
desktop service initialization; **address, undefined-behavior and leak detection
remain enabled**. This does not claim the original desktop host is leak-free.
No upstream or system library was patched and no sanitizer finding was hidden.

## Performance

The reproducible command `python3 tools/benchmark.py build-validation` summarizes
23 freshly extracted frames. Final measured values are in
[benchmark.txt](../validation/benchmark.txt). The largest fixture has 1080 fields
and 1131 tiles. These timings exclude process/dissector-registration startup.

Extraction and model construction are one measured traversal. Geometry time is
measured separately. The UI reports buffer-upload CPU submission time and time
from model submission to the first paint; these are not GPU-completion fence
measurements or display-scanout latency. Measurement precision and driver behavior
limit interpretation. This is a bounded benchmark, not a real-time guarantee.

## NOT TESTED

The 11 upstream skips comprise six disabled live-capture tests, four Stratoshark
tests (not built), and one Lua test (disabled in this configuration). See the
raw pytest report for exact cases. Windows, macOS, ARM and alternate GPU drivers
were unavailable and are NOT TESTED. No claim is made for exhaustive dissector,
decryption/decompression, live-capture, or every malformed-input coverage.
The initial commit’s complete hosted workflow succeeded (run 34127913363).
That historical result does not establish the outcome of a later commit’s CI run.
