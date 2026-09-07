# Stateful Semantic Protocol Analyzer

A native Wireshark extension for deterministic transaction correlation,
publisher-state observations and temporal semantic differences. It consumes
Wireshark's decoded fields and preserves their frame/field provenance. The core
works offline. Optional AI explains reviewed semantic context; it cannot modify
protocol state or deterministic findings.

**Target:** Wireshark **4.7.4 development**, commit
`9fc76ca769c9226b3d484cc43e5b62289fab1da3`. Validated on Ubuntu 24.04.4 with
Qt 6.4.2 and GCC 13.3.0. This module does not load into Wireshark 4.2.2.
Native Windows/macOS runtime and field deployment are **NOT TESTED**.

The analyzer is independent of 3DPacketViewer and shares its pinned native build.
See the [repository overview and R-GOOSE video](../README.md).

## Implemented protocol scope

| Protocol | Implemented analysis |
|---|---|
| IEC 60870-5-104 | Activation/confirmation/termination correlation, transfer-control exchanges, sequence observations, measurements and configured policy checks |
| GOOSE / decoded R-GOOSE | Publisher identity, stNum/sqNum progression, configuration/dataset changes and observed publication gaps |
| Sampled Values | Stream identity, sample-counter continuity and configured rate/modulus checks; decoded values depend on Wireshark's matching profile |
| MMS | Confirmed request/response/error envelopes and invoke-ID correlation |
| Modbus/TCP | Transaction/function matching, exceptions, writes and decoded register observations |
| DNP3 | Basic application request/response/fragments, unsolicited confirmations and control classification |

These are bounded observation profiles, not complete standards implementations.
See [rule predicates, assumptions and legitimate alternatives](docs/PROTOCOLS.md).
R-GOOSE cryptographic verification, full MMS association semantics and complete
DNP3 authentication/control profiles are outside scope.

## Build and launch

From the repository root, after installing the
[Wireshark/Qt dependencies](../docs/BUILD.md):

```sh
python3 tools/build.py --wireshark ../wireshark-pinned --build ../ws-build --jobs 4
../ws-build/run/wireshark
```

Both native modules build by default. Installation follows the same Wireshark
build's `cmake --install` operation and versioned UI plugin directory.
See [platform and packaging instructions](docs/BUILD.md).

## Offline workflow

1. Open a capture, then **Tools → Stateful Semantic Protocol Analyzer →
   Protocol Transactions**. The viewer performs one retap of the open capture.
2. Inspect a transaction's operation, object, endpoints/roles, completion,
   transitions and contributing frames. Measurements/publications are labeled
   observations, not invented request-response exchanges.
3. Use **Semantic Timeline / Events** for the ordered event table. Double-click
   an event to navigate; **Show contributing packets** applies a frame filter.
4. Select events/transactions and choose a context: selected packets, a flow,
   publisher, protocol, device, time window, frame range or capture summary.
5. Click **Analyze Semantic Differences (local)** for deterministic statistics
   and the sanitized context. Comparison modes accept another range/entity ID.

Numeric differences align matching measurement identities only. Different
devices/streams retain separate summaries; units and signal equivalence are not
guessed. Missing requests, capture boundaries and unresolved observations retain
explicit status. Load optional asset/topology policy through the toolbar;
configured policy findings remain distinct from protocol observations.

State is bounded at 200,000 events, 50,000 transactions or 50,000 findings;
reaching a limit produces a partial-results diagnostic. Full-tree dissection
adds work while the viewer is open. Closing it unregisters the tap.

## Optional AI workflow

AI starts **unchecked** in every new viewer.

1. Configure `OPENCODE_API_KEY` before launch or enter a session key in the
   masked field. The application does not save the key in settings.
2. Check **Enable AI Explanation / Analysis**, click **Refresh Models**, and
   choose a currently discovered OpenCode Go model.
3. Choose the semantic context and an analysis/explanation action.
4. Inspect **View AI Request**. It shows the exact outbound JSON; **Cancel**
   sends nothing. **Send** transmits that body over HTTPS.
5. Read the explicitly labeled **AI-Generated Explanation** or
   **AI-Derived Observation** and activate an evidence-frame reference.
6. Uncheck AI to cancel outstanding requests and prevent discovery/analysis
   requests. Offline state and deterministic findings remain available.

The outbound allowlist excludes raw PCAPs, raw bytes, arbitrary payload text,
hidden fields and unfiltered dissection trees. Endpoint/dataset names are
pseudonymized; allowed numeric semantic values remain visible in the preview.
Sanitization does not make operational information non-sensitive.

AI responses are schema/evidence checked and cannot overwrite deterministic
results. They remain unverified interpretations. Provider errors are isolated
from packet analysis. **Test Connection** checks TLS/catalog reachability, not
API-key authentication; a successful analysis establishes authentication.

Models/API mappings depend on provider discovery and supported endpoint
documentation. Unknown mappings fail closed. Availability, use restrictions and
retention depend on the provider; read [OpenCode Go's documentation](https://opencode.ai/docs/go/)
and the [privacy/AI contract](docs/PRIVACY.md) before enabling it.

## Headless export and tests

The native CLI uses Wireshark EPAN and does not link Qt Network:

```sh
../ws-build/run/semantic_analyze capture.pcap report.json
# Optional policy: append policy.json as the third argument.
```

Deterministic reports retain local endpoint identities. AI exports are separate.
Handle both as sensitive analysis artifacts.

```sh
# From the repository root; offline core/provider/privacy tests, no UI plugin.
cmake -S semantic -B build-semantic -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-semantic
ctest --test-dir build-semantic --output-on-failure

# Synthetic Wireshark-backed integration checks after the native build.
python3 semantic/tools/make_fixtures.py
python3 semantic/tests/integration/validate.py \
  --analyzer ../ws-build/run/semantic_analyze --tshark ../ws-build/run/tshark \
  --fixtures build-semantic-fixtures --output build-semantic-validation
```

Native GUI tests require the opt-in development flags documented in
[BUILD.md](docs/BUILD.md). Executed outcomes and untested cases are recorded in
[VALIDATION.md](docs/VALIDATION.md).

[Architecture](docs/ARCHITECTURE.md) ·
[Assets, policies and contexts](docs/CONFIGURATION.md) ·
[Protocol rules and extension guide](docs/PROTOCOLS.md) ·
[Privacy](docs/PRIVACY.md) · [Limitations](docs/LIMITATIONS.md)

License: [GPL-2.0-or-later](../LICENSE).
