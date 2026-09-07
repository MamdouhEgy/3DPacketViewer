# Build and installation

## Linux (executed platform)

Pin the exact upstream SHA in `cmake/wireshark-revision.txt`; the integration
script refuses any other commit. Do not vendor Wireshark into this repository.

Ubuntu 24.04 dependency setup (requires system package administration):

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build git python3 \
  qt6-base-dev qt6-tools-dev qt6-tools-dev-tools qt6-svg-dev \
  libglib2.0-dev libgcrypt20-dev libc-ares-dev libpcap-dev libpcre2-dev \
  libxml2-dev libspeexdsp-dev flex bison
python3 tools/build.py --wireshark ../wireshark-pinned --build ../ws-build --jobs 4
../ws-build/run/wireshark
```

The build helper clones/fetches the pinned revision only when the requested
source directory does not exist. It leaves existing unrelated checkouts intact.
It creates a source-directory link at `plugins/ui/3dpacketviewer`, then configures
`CUSTOM_PLUGIN_SRC_DIR=ui/3dpacketviewer`. Existing unrelated links/directories
are rejected. Repeated integration is idempotent. If other custom plugins are
required, configure the semicolon-separated CUSTOM_PLUGIN_SRC_DIR list manually.
The helper defaults to the full upstream optional-dependency detection.

The validation machine lacked passwordless sudo. Development packages were
instead extracted under a temporary local prefix. This is an environment
bootstrap, not a required project installation method. Its build used these
additional options:

```sh
-DENABLE_LUA=OFF -DENABLE_GNUTLS=OFF -DENABLE_KERBEROS=OFF \
-DBUILD_stratoshark=OFF -DBUILD_mmdbresolve=OFF
```

Those optional features are not required by the plugin. Decryption functionality
available in a full Wireshark build was not validated in this reduced environment.

To configure a previously prepared checkout explicitly:

```sh
python3 tools/integrate.py ../wireshark-pinned
cmake -S ../wireshark-pinned -B ../ws-build -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCUSTOM_PLUGIN_SRC_DIR=ui/3dpacketviewer
cmake --build ../ws-build --parallel 4
```

For an installation prefix, configure Wireshark's CMAKE_INSTALL_PREFIX and run
`cmake --install ../ws-build`. The plugin follows upstream install_plugin and
installs below the versioned `wireshark/plugins/4.7/ui` library directory.
For development the loader uses `ws-build/run/plugins/wireshark/4.7/ui`.
This repository does not overwrite a distribution-installed Wireshark.

## Tests

```sh
# Wireshark-independent core tests
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
# Synthetic fixtures and dissection oracle
python3 tools/make_fixtures.py
python3 tests/integration/validate.py --bin ../ws-build/run \
  --fixtures build-fixtures --output build-validation
python3 tools/benchmark.py build-validation
```

For actual in-process Wireshark GUI validation, reconfigure with
`-DPACKETVIEWER_GUI_TESTS=ON` and rebuild. This explicitly opt-in test driver is
compiled out by default. It activates only when PACKETVIEWER_TEST_DIR is set,
uses synthetic captures, records results, and closes Wireshark.

```sh
python3 tools/run_gui.py --wireshark ../ws-build/run/wireshark \
  --fixtures build-fixtures --output build-gui
# In a headless Linux CI session:
xvfb-run -a python3 tools/run_gui.py --wireshark ../ws-build/run/wireshark \
  --fixtures build-fixtures --output build-gui --no-session-bus
```

Upstream checks used: build `test-programs`, then pytest's suite_unittests.py,
suite_fileformats.py, and suite_clopts.py with `--program-path` pointing at run,
`--disable-capture --disable-gui`. The project GUI tests are run separately.
Run upstream `tools/check_apis.py` on the plugin sources; clang-format 18 uses
the repository's four-space, no-tab style configuration.

For a separate fully instrumented build:

```sh
python3 tools/build.py --wireshark ../wireshark-pinned --build ../ws-asan \
  --jobs 4 --sanitizers --gui-tests
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ../ws-asan/run/packetviewer_core_tests
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/integration/validate.py --bin ../ws-asan/run \
  --fixtures build-fixtures --output build-asan-validation
```

Read the executed sanitizer findings before interpreting GUI process exit codes.
No sanitizer suppression file is supplied.

## Native Windows (NOT TESTED)

Use the pinned Wireshark source's `doc/wsdg_src/wsdg_build_intro.adoc` and
Windows build chapter as the toolchain authority. At this revision the official
guide recommends Visual Studio 2026 with the Desktop development with C++
workload, an x64 native developer shell, matching x64 Qt 6.5.3 or newer,
CMake, Python 3 and Git. Run the official Wireshark Windows dependency setup
for this checkout; set WIRESHARK_BASE_DIR, WIRESHARK_LIB_DIR and the Qt prefix
according to that guide. Qt must include OpenGL and OpenGLWidgets.

Enable Windows Developer Mode for directory symlinks, or use a Windows directory
junction for `plugins\ui\3dpacketviewer` pointing to this independent repository.
Then, in the Visual Studio native tools prompt:

```powershell
python tools/integrate.py ..\wireshark-pinned
cmake -S ..\wireshark-pinned -B ..\ws-build -G Ninja `
  -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DCUSTOM_PLUGIN_SRC_DIR=ui/3dpacketviewer `
  -DCMAKE_PREFIX_PATH=C:\Qt\<matching-version>\<msvc-kit>
cmake --build ..\ws-build --parallel 4
..\ws-build\run\Wireshark.exe
```

Use a Qt kit compatible with the compiler/runtime and architecture. Do not mix
MinGW Qt with MSVC Wireshark. UI-plugin DLL placement and deployment of Qt
runtime DLLs follow upstream CMake packaging, not a Linux `.so` copy recipe.
These commands are native Windows guidance, not a claim of an executed build.

## macOS (NOT TESTED)

Use the official pinned Wireshark macOS dependency setup, Xcode/Clang, CMake,
Ninja and a matching Qt >=6.5.3 with OpenGLWidgets. Integrate the source as above
and use upstream bundle/installation targets. The code requests desktop OpenGL
2.1, GLSL 1.20 and public Qt APIs; it uses no Qt private or platform-specific
rendering APIs. Apple OpenGL driver behavior and bundle plugin loading still
require validation on macOS hardware.
