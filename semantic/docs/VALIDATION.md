# Executed validation — 2026-09-07

Latest follow-up: the R-GOOSE correction below passed 39 core tests, 15 network tests, 200 integration assertions and 40 native GUI checks. The original delivery table is retained as historical evidence.

Target: Wireshark 4.7.4 development, `9fc76ca769c9226b3d484cc43e5b62289fab1da3`; Ubuntu 24.04.4 x86-64, Qt 6.4.2, GCC 13.3.0, CMake 3.28.3, Ninja 1.11.1. Results below describe executed tests, not general certification.

| Gate | Executed result |
|---|---|
| Fresh standalone Debug configure/build | PASS; core, serializer, provider, AI panel and tests built from an empty build directory |
| Native release configure/build | PASS; final UI module built with `SSPA_GUI_TESTS=OFF`; upstream EPAN/dissectors rebuilt during final release configure |
| Offline core/context/privacy unit suite | 38 passed, 0 failed (includes Qt initialization/cleanup cases) |
| Deterministic network transport regression | 15 passed, 0 failed (includes Qt initialization/cleanup cases) |
| Synthetic capture integration and independent field-location checks | 167 passed, 0 failed |
| Installed user-bundle native GUI | 36 passed, 0 failed; installed-library compatibility and clean shutdown verified |
| Native offline GUI under ASan/UBSan | 36 passed, 0 failed; process exited normally with code 0 |
| Live OpenCode GUI acceptance run | 43 passed, 0 failed; includes 36 offline GUI checks plus 7 live acceptance checks; normal process exit code 0 |
| ASan/UBSan unit and network suites | 38 + 15 passed; no sanitizer error |
| ASan/UBSan fixture integration | 167 passed; no sanitizer error |
| Live AI GUI under ASan/UBSan, with validated libproxy 0.5.12 | 43 passed, process exit 0; no sanitizer report |
| Libproxy 0.5.12 upstream regression | 6 suites passed, 0 failed |
| Wireshark upstream file-format / command-line suites | 44 passed, 11 skipped; executed with instrumented binaries |
| Wireshark source API checker | 0 warnings |
| Source credential-pattern scan | 0 credential-token patterns found |

The 11 upstream skips concern disabled live capture, Lua, and Stratoshark, as recorded in `results/upstream.txt`. Native Windows, macOS, real-interface live capture, sustained industrial-rate SV capture, full MMS association negotiation, all DNP3 profiles, TLS failure against a deliberately invalid remote certificate, and a field deployment on real OT traffic are **NOT TESTED**. Certificate verification is configured in production requests, and transport failures are tested with an injected local test transport.

## End-to-end live acceptance

The actual native Wireshark viewer opened the synthetic IEC104 capture. The command used activation frame 6, confirmation 7 and termination 8: measured duration 42 ms. Frames 9–12 contain Wireshark-decoded IEEE-754 single-precision values approximately 101.2, 102.1, 150.4 and 151.0, spaced one second apart. Computed deltas/rates preserve decoded floating-point precision; they are not rounded into invented exact wire values.

The user-enabled AI checkbox initiated dynamic catalog/API discovery. The selected discovered model was `gpt-5.6-luna`, Responses API. The reviewed request contained only frames 9–12, 12,721 JSON bytes, and a 2048-token response limit. Request timestamp: `2026-09-07T19:37:59.481Z`. The response was accepted as `AI_DERIVED_OBSERVATION`; its evidence-frame navigation reached the corresponding Wireshark packet. Disabling AI prevented new discovery requests. Deterministic event/finding state remained unchanged.

Only synthetic information was sent. The test key was supplied over echo-disabled stdin, kept in memory and not written to source, reports or logs. The request and validated result are retained in `results/synthetic-ai-request.json` and `results/synthetic-ai-result.json`; neither contains a credential. The provider's free-text conclusion is not treated as independent protocol truth.

## Protocol fixtures actually exercised

- IEC104: normal U-format and command sequence, measurements, missing confirmation/termination, capture boundary, transmit-sequence discontinuity, modulo wrap, segmentation/reassembly, TCP retransmission, multiple PDUs per frame, SQ-derived sequential IOAs, synthetic drift and repeated small bias.
- GOOSE: normal state progression, stNum regression and source changes for the same logical publisher.
- SV: counter gaps and configured modulo-4000 wrap. These tests validate metadata/counters, not arbitrary dataset scaling.
- MMS: synthetic exported-PDU confirmed identify request/response, invokeID and service correlation.
- Modbus/TCP: read and single-register write request/response; policy-based unexpected write source.
- DNP3: synthetic application read/response with valid transport/link CRC construction and application sequence correlation.

Fixture source bytes and timestamps are version-controlled in `tests/fixtures/packets.json`; `tools/make_fixtures.py` must reproduce them exactly. Generated PCAPs remain ignored. The generator constructs traffic; it is never linked to the analyzer or used as a protocol parser.

## Ground truth and oracle distinction

`results/wire-validation.csv` records manually derived Ethernet/IPv4/TCP/APCI/ASDU and Modbus offsets, expected widths, extracted source-relative offsets/widths and PASS/FAIL. The known IEC104 IOA begins at byte 66 and the float at 69 for these particular fixtures. Those numbers are assertions about constructed fixtures, never hard-coded extraction layouts.

The integration suite separately compares decoded fields with tshark. This establishes agreement with Wireshark, not independent standards certification. The two checks are intentionally separate. Reassembled IEC104 events carry completion-frame provenance and additional data-source metadata; no original-frame byte contiguity is invented.

## Failure isolation and privacy regression

Executed tests cover AI-off zero requests, cancellation, dynamic adapter discovery, unknown/disappearing model IDs, authentication failure, rate limiting, unavailable service, redirects, timeout, transport failure, malformed catalog, invalid/oversized JSON, invented evidence frames, unexpected response properties and credential echo rejection. Exact sent bodies are compared to prepared bodies with the injected network transport. Packet-like payload/password/raw-byte/display strings and hostile instructions are rejected by the allowlist; endpoint/dataset strings become tokens. A partial packet context cannot disclose the state/latency of a transaction involving unselected packets. Concurrent transactions, stale-state reset, non-finite numbers, unsafe integers and zero/negative timing differences are covered.

## Performance observations

The 21 fixture captures' final release CLI process runtimes had median 83.176 ms and maximum 93.549 ms on this machine. These include EPAN startup, file I/O, extraction, state processing, serialization and process teardown; they are **not** per-packet tap latency or an industrial throughput claim. Exact rows are in `results/benchmark.json`. A 10,000-event unit regression verifies bounded context summarization over all selected observations. The viewer uses Qt models, not one widget per event, and never automatically rescans on every packet selection.

The full-tree tap requirement adds Wireshark dissection work while the viewer is open. Event/transaction/finding limits are explicit; reaching them yields partial-results diagnostics. No claim is made that the current limits support unbounded live captures or every industrial SV rate.

The final endpoint-provenance regression checks all 21 fixtures for nonempty source/destination identity. Exported-PDU MMS uses visible exported-PDU address fields; events lacking endpoint identity are retained but excluded from correlation.

## State versus measurement statistics

Executed regressions ensure that COT, quality masks, sequence/configuration codes, Boolean values and decoded double-point states use observation/change counts rather than measurement means or rates. Numeric measurement series retain deterministic differences, timing and summary statistics. The final live request includes this distinction.

## Isolated dependency leak

The real-network sanitizer run passed all 43 functional assertions but exited with code 1 after LeakSanitizer reported 141 bytes in six allocations. Stacks enter `g_list_append` / `g_strdup` from `libpxbackend-1.0.so`, through `px_proxy_factory_new` and Qt's `QNetworkProxyFactory::systemProxyForQuery`. The standalone `tools/diagnostics/qt_proxy_leak.cpp`, which uses neither Wireshark nor the analyzer, reproduces exactly 141 bytes/six allocations on this host. The independent diagnostic report is retained in `results/proxy-leak-asan.txt`. No suppression or change to proxy routing was made. This original live-network sanitizer attempt was **FAIL** and is retained separately as `results/live-asan-system-proxy-process.json`.

The normal final live run exited with code 0. An earlier normal launch was terminated by signal 9 before producing any checks; the cause was not established and that launch is not counted as a successful run. The successful rerun's process result and 43 assertions are retained.

GitHub Actions full native build and GUI validation passed for implementation commit `ac41a2a9448db58de60bceb61fc877b428db1753` ([run 34153308989](https://github.com/MamdouhEgy/3DPacketViewer/actions/runs/34153308989)). Final state-statistics changes were additionally rebuilt and tested locally as recorded above; subsequent CI status must be read from the repository rather than inferred from this earlier run.

Resolution: the unmodified upstream libproxy 0.5.12 release, commit `99da01926b1b1e303a4d2331bbd74bed424863e7`, was built with all applicable default proxy/PAC backends and passed its six upstream test suites. It contains the upstream [list/sysconfig deallocation fixes](https://github.com/libproxy/libproxy/pull/312). The standalone diagnostic then exited with code 0 and no sanitizer report. The complete live Wireshark AI test with this library passed all 43 checks and exited with code 0 under ASan/UBSan. This dependency is installed only in the user bundle, and its launcher resolves it through that bundle's library directory. System packages and proxy configuration are unchanged. LGPL license and source revision are installed alongside the dependency.

## R-GOOSE correction — executed follow-up

The original extractor recognized the Ethernet `goose` tree but not the routed `r-goose` tree, causing captures containing decoded R-GOOSE to show zero semantic events. The correction recognizes the actual routed tree, obtains APPID from `rgoose.appid`, scopes each decoded GOOSE PDU separately, preserves IP publisher identity, and separates routed/Ethernet publisher state. No packet parser was added.

Executed: 39 core tests, 15 network tests, 200 fixture/integration assertions over 24 synthetic captures, and 40 native GUI checks passed. Core, fixture and GUI tests also passed under ASan/UBSan. The GUI process exited with code 0. New fixtures include normal routed GOOSE, stNum regression and two independent APPIDs in one datagram. The constructed first APPID is independently located at byte 75 with width 2; tshark separately confirms its value. Tshark's hexadecimal APPID presentation is handled explicitly by the integration oracle.

An additional user-supplied capture was checked locally. Its contents, identities, derived counts and local report were not committed or sent to an AI service. This check is not a security verdict or cryptographic verification. Remote AI was not invoked for this follow-up; the new allowlisted routed flag was covered by local privacy regression. Artifacts are the `results/rgoose-*` files.
