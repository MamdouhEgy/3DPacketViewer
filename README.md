# 3DPacketViewer + Stateful Semantic Protocol Analyzer

Two native Wireshark extensions for packet inspection, protocol teaching and
OT/smart-grid analysis. Wireshark supplies the decoded fields. The extensions
add field-location views and deterministic analysis across packets.

| Tool | Question it answers | Main capabilities |
|---|---|---|
| **3DPacketViewer 0.2.0** | Where is this decoded field encoded? | Byte & bit map, source-relative offsets, raw hex/binary values, field inspector and interactive 3D protocol stack |
| **Stateful Semantic Protocol Analyzer 0.1.0** | How do decoded operations and observations relate over time? | Transaction correlation, publisher state, configured policy checks, temporal differences and evidence-linked findings |

The tools are independent modules in one repository. The visualizer has no
network client. The semantic engine works offline; its optional AI component
receives only a reviewed, allowlisted semantic context.

## Watch the 60-second R-GOOSE demonstration

https://github.com/user-attachments/assets/9ee6e2f7-3caa-4f56-9b3f-5ec8f9484b0d

The silent, captioned video opens `Routable_GOOSE.pcap`, rotates and explodes the
3D stack, locates `goose.stNum` in the Byte & bit map, and examines publisher
observations in the semantic analyzer. It then shows a real OpenCode Go/Luna
response, navigation to evidence frame 12, and disabling AI. Provider waiting
time is shortened. See [chapters and interpretation](docs/DEMO.md).

The video demonstrates the workflow, **not R-GOOSE security certification**.
Signatures/HMACs, key management and authenticated replay protection are outside
the implemented scope. Access to the private repository is required to view its
attachment.

## Compatibility

| Item | Validated configuration |
|---|---|
| Wireshark | **4.7.4 development** |
| Exact upstream commit | `9fc76ca769c9226b3d484cc43e5b62289fab1da3` |
| Platform | Ubuntu 24.04.4, x86-64 |
| Toolchain | Qt 6.4.2; GCC 13.3.0; CMake 3.28.3; Ninja 1.11.1 |
| Integration | Source-integrated Qt UI plugins; modeless Wireshark-owned windows |
| Other platforms | Native Windows and macOS runtime **NOT TESTED** |

Build and install both modules with the pinned **Wireshark 4.7.4 development**
revision. The integration script checks the revision
and links this repository into the upstream build; it does not vendor Wireshark
or patch its implementation files.

## Build and open

Requirements: C++20, Python 3, Git, CMake, Ninja, Qt 6
Core/Gui/Widgets/OpenGL/OpenGLWidgets/Network/Test, and Wireshark's development
dependencies. Install the platform dependencies from [BUILD.md](docs/BUILD.md),
then run these commands from the repository root:

```sh
# Fetch the pinned upstream checkout if the source directory does not exist.
# Build both native plugins and Wireshark.
python3 tools/build.py --wireshark ../wireshark-pinned --build ../ws-build --jobs 4
../ws-build/run/wireshark
```

Open a capture, select a packet, then use:

- **Tools → 3DPacketViewer → Open 3D packet viewer**
- **Tools → Stateful Semantic Protocol Analyzer → Protocol Transactions**

For installation, configure Wireshark's `CMAKE_INSTALL_PREFIX`, then run
`cmake --install ../ws-build`. The modules install under the versioned
`wireshark/plugins/4.7/ui` library directory. Do not copy them into an unrelated
Wireshark installation. See [native build and packaging](semantic/docs/BUILD.md).

## Inspect fields and protocol layers

Select a field in the map or tree. The inspector shows Wireshark's decoded value,
source-relative offset, container length, bit metadata and provenance. The map
and raw view highlight the corresponding bytes/bits in that data source.
Use **Emphasize protocol** and 4/8/16 bytes per row to simplify the view.

The **3D protocol stack** adds these interactions; equivalent toolbar controls
are available:

| Input | Action |
|---|---|
| Left drag / wheel / middle or right drag | Orbit / zoom / pan |
| Double click | Fit selected canonical field, otherwise the scene |
| R / F | Reset / fit packet |
| E / O | Explode layers / switch projection |
| L / G / Escape | Labels / generated-field tree entries / clear selection |

Packet selection updates the viewer automatically. Native Packet Details field
selection updates the plugin; reverse selection of an individual native field
is not exposed by the plugin API.

## Analyze transactions and temporal context

The semantic analyzer supports implemented profiles for IEC 60870-5-104,
GOOSE/R-GOOSE, Sampled Values, MMS, Modbus/TCP and DNP3. Coverage differs by
protocol: MMS confirmed-service envelopes and basic DNP3 application correlation
are narrower than full protocol conformance. See the exact
[protocol scope and rule assumptions](semantic/docs/PROTOCOLS.md).

Select transactions or events, choose a context, then use **Analyze Semantic
Differences (local)**. Contexts include selected packets, flows, publishers,
time windows, frame ranges and comparisons. Statistics are computed locally.
Contributing-frame navigation and filtering link results back to Wireshark.

For optional AI: enable the checkbox, configure a session key or
`OPENCODE_API_KEY`, refresh models, select a model, and open **View AI Request**.
Only **Send** transmits the reviewed JSON. AI output is labeled separately and
cannot overwrite deterministic findings. See the complete
[semantic workflow](semantic/README.md) and [privacy boundary](semantic/docs/PRIVACY.md).

## Interpretation and limits

- Geometry follows represented bit ranges. Row wrapping, color, thickness and
  Z separation are presentation choices; object volume is not a packet quantity.
- Generated fields consume no wire bits. Additional/reassembled buffers remain
  separate sources. Overlapping interpretations do not add independent bytes.
- Unmapped bits are not automatically payload. Units, signal identities and
  missing capture evidence are not invented.
- A state change, timing observation or policy violation does not by itself
  establish an attack. AI hypotheses remain unverified interpretations.
- Validation uses bounded fixtures and documented GUI runs. This is not
  exhaustive standards certification or field-deployment validation.

## Tests and documentation

```sh
# Builds independent components for both tools; no Wireshark module is produced.
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

| Topic | Visualizer | Semantic analyzer |
|---|---|---|
| Design | [Architecture](docs/ARCHITECTURE.md) | [Architecture](semantic/docs/ARCHITECTURE.md) |
| Interpretation | [Scientific validity](docs/SCIENTIFIC_VALIDITY.md) | [Protocol rules](semantic/docs/PROTOCOLS.md) |
| Executed results | [Validation](docs/VALIDATION.md) | [Validation](semantic/docs/VALIDATION.md) |
| Remaining scope | [Limitations](docs/LIMITATIONS.md) | [Limitations](semantic/docs/LIMITATIONS.md) |
| Configuration | [Build and controls](docs/BUILD.md) | [Assets, policies and contexts](semantic/docs/CONFIGURATION.md) |

License: [GPL-2.0-or-later](LICENSE), compatible with Wireshark linkage.
