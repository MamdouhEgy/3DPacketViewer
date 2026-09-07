# Build, compatibility and installation

Validated target source: Wireshark 4.7.4 development at `9fc76ca769c9226b3d484cc43e5b62289fab1da3`.
Environment: Ubuntu 24.04.4 x86-64, Qt 6.4.2, GCC 13.3.0, CMake 3.28.3, Ninja 1.11.1. Linux is the executed platform. Windows and macOS are NOT TESTED for this extension.

This revision's native UI-plugin mechanism is integrated through Wireshark's CMake tree. The repository is independent, with an idempotent source link and pinned-revision guard in `tools/integrate.py`. No Wireshark implementation file is patched or vendored. `semantic_analyzer` is a separate module target below `semantic/`, sharing upstream registration/install helpers. It links `sspa_extraction`, `sspa_ai_ui`, EPAN and uiqt_plugin. Native UI requires the exact compatible Wireshark ABI; a module compiled here must not be copied into Wireshark 4.2.2.

Follow the repository [Linux dependency and build instructions](../../docs/BUILD.md). Qt Network and Qt Test are supplied by Qt Base. Configure `BUILD_SEMANTIC_ANALYZER=ON` (default). The resulting module is `run/plugins/wireshark/4.7/ui/semantic_analyzer.so`; platform suffixes follow Wireshark. `cmake --install` uses the upstream versioned plugin location.

A standalone configure (`cmake -S semantic -B build-semantic`) builds the offline core, serializer, provider, AI panel, and tests without Wireshark. It does not pretend to produce a loadable Wireshark module. Use the native build for `semantic_analyzer` and `semantic_analyze`.

## Native Windows

Use the pinned revision's official Windows Developer Guide/toolchain, a Visual Studio 2022 x64 development prompt, CMake, matching Qt 6 libraries and Wireshark's dependency bundle. Read `doc/README.windows` and the current [official developer guide](https://www.wireshark.org/docs/wsdg_html/) for required versions. The repository's integration helper creates a directory link; Windows must permit directory symlinks (Developer Mode or appropriate privilege). Configure the linked checkout with `CUSTOM_PLUGIN_SRC_DIR=ui/3dpacketviewer`, then build the Release configuration and install the resulting versioned UI module alongside that same Wireshark build. Do not combine toolchain/Qt/ABI variants. Native Windows execution and credential-entry behavior were NOT TESTED here.

## macOS

Use the same pinned source and upstream macOS dependency instructions, CMake and compatible Qt 6. Code uses public Qt APIs and no Linux-only production provider calls. App-bundle installation/signing follows Wireshark's own packaging. Runtime loading and notarization were NOT TESTED here.

## Testing and sanitizers

`semantic_core_tests` validates offline state, contexts, statistics and privacy. `semantic_network_tests` injects a deterministic Qt network transport for catalog, cancellation and failure-path regression tests. They require no Internet/key. The full native CLI fixture test compares field provenance to manually derived locations and compares decoded values to tshark as a separate oracle.

Set `SSPA_GUI_TESTS=ON` only for development. `SSPA_TEST_DIR` activates the synthetic native GUI driver and normal application shutdown; it is compiled out by default. The runner uses an isolated profile, unsets packet-viewer test hooks and removes `OPENCODE_API_KEY` for offline tests. A headless Linux runner may use `xvfb-run -a`.

For the opt-in live synthetic AI test, add `--live-ai` to `semantic/tools/run_gui.py`. The runner disables terminal echo, hands the session key to the test via stdin, and sends only a reviewed synthetic frame range. It never passes a key on the command line or writes it to a file. This mode is excluded from CI and should not be enabled on real captures.

Configure a separate upstream Debug build with `ENABLE_ASAN=ON` and `ENABLE_UBSAN=ON`, compile the native module/tests, then run unit, fixture and GUI checks with `ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1`. The GUI runner isolates desktop DBus services to avoid unrelated platform-service leak retention; it does not suppress sanitizer findings. See executed results in VALIDATION.md.

The live AI sanitizer run exposed a system-libproxy shutdown leak independently reproduced with `tools/diagnostics/qt_proxy_leak.cpp`. To reproduce on a system with Qt development packages:

```sh
c++ -fsanitize=address -g semantic/tools/diagnostics/qt_proxy_leak.cpp -o /tmp/qt-proxy-leak $(pkg-config --cflags --libs Qt6Core Qt6Network)
ASAN_OPTIONS=detect_leaks=1 /tmp/qt-proxy-leak
```

This diagnostic queries system proxy configuration. It does not authenticate, send semantic content, or load the plugin. No workaround disables the operator's proxy settings and no leak suppression is installed.

## Verified Linux proxy dependency

The user bundle uses unmodified [libproxy 0.5.12](https://github.com/libproxy/libproxy/releases/tag/0.5.12), commit `99da01926b1b1e303a4d2331bbd74bed424863e7`, to resolve the host's older-library shutdown leak. This is a packaging dependency, not a Wireshark/semantic-engine patch. Linux build dependencies are Meson (validated 1.7.2), Ninja, a C compiler, GLib/GIO development files, libcurl development files, Duktape development files and `gsettings-desktop-schemas-dev`. Keep the default applicable proxy backends enabled.

```sh
git clone https://github.com/libproxy/libproxy.git libproxy-source
git -C libproxy-source checkout 99da01926b1b1e303a4d2331bbd74bed424863e7
meson setup libproxy-build libproxy-source --prefix="$PWD/libproxy-stage" --libdir=lib --buildtype=release -Ddocs=false -Dintrospection=false -Dvapi=false
meson compile -C libproxy-build
meson test -C libproxy-build --print-errorlogs
meson install -C libproxy-build
python3 semantic/tools/install_proxy_dependency.py --source libproxy-source --stage libproxy-stage --prefix "$HOME/.local/opt/wireshark-4.7.4-3dpacketviewer" --launcher "$HOME/.local/bin/wireshark-3d"
```

The installer verifies the source revision, keeps libraries confined to the existing user bundle, relocates their runtime lookup paths and installs licensing/source metadata. It updates that bundle's launcher to load its libraries; launching the raw executable without the wrapper can instead select the old system proxy dependency. Distribution-wide updates are not performed. For an isolated sanitizer test before installation, set `LD_LIBRARY_PATH` to the staged `lib` directory; this changes dependency selection, not leak detection or proxy settings.
