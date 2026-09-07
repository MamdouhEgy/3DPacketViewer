# Executed validation — 2026-09-07

Target: Wireshark 4.7.4 development, `9fc76ca769c9226b3d484cc43e5b62289fab1da3`; Ubuntu 24.04.4 x86-64, Qt 6.4.2, GCC 13.3.0, CMake 3.28.3, Ninja 1.11.1. Results below describe executed tests, not general certification.

| Gate | Executed result |
|---|---|
| Fresh standalone Debug configure/build | PASS; core, serializer, provider, AI panel and tests built from an empty build directory |
| Native release configure/build | PASS; final UI module built with `SSPA_GUI_TESTS=OFF`; upstream EPAN/dissectors rebuilt during final release configure |
| Offline core/context/privacy unit suite | 36 passed, 0 failed (includes Qt initialization/cleanup cases) |
| Deterministic network transport regression | 15 passed, 0 failed (includes Qt initialization/cleanup cases) |
| Synthetic capture integration and independent field-location checks | 167 passed, 0 failed |
| Installed user-bundle native GUI | 36 passed, 0 failed; installed-library compatibility and clean shutdown verified |
| Native offline GUI under ASan/UBSan | 36 passed, 0 failed; process exited normally with code 0 |
| Live OpenCode GUI acceptance run | 42 passed, 0 failed; includes the then-current 35 offline GUI checks plus 7 live acceptance checks; not 42 additional independent tests |
| ASan/UBSan unit and network suites | 36 + 15 passed; no sanitizer error |
| ASan/UBSan fixture integration | 167 passed; no sanitizer error |
| Wireshark upstream file-format / command-line suites | 44 passed, 11 skipped; executed with instrumented binaries |
| Wireshark source API checker | 0 warnings |
| Source credential-pattern scan | 0 credential-token patterns found |

The 11 upstream skips concern disabled live capture, Lua, and Stratoshark, as recorded in `results/upstream.txt`. Native Windows, macOS, real-interface live capture, sustained industrial-rate SV capture, full MMS association negotiation, all DNP3 profiles, TLS failure against a deliberately invalid remote certificate, and a field deployment on real OT traffic are **NOT TESTED**. Certificate verification is configured in production requests, and transport failures are tested with an injected local test transport.

## End-to-end live acceptance

The actual native Wireshark viewer opened the synthetic IEC104 capture. The command used activation frame 6, confirmation 7 and termination 8: measured duration 42 ms. Frames 9–12 contain Wireshark-decoded IEEE-754 single-precision values approximately 101.2, 102.1, 150.4 and 151.0, spaced one second apart. Computed deltas/rates preserve decoded floating-point precision; they are not rounded into invented exact wire values.

The user-enabled AI checkbox initiated dynamic catalog/API discovery. The selected discovered model was `gpt-5.6-luna`, Responses API. The reviewed request contained only frames 9–12, 15,610 JSON bytes, and a 2048-token response limit. Request timestamp: `2026-09-07T18:12:11.769Z`. The response was accepted as `AI_DERIVED_OBSERVATION`; its evidence-frame navigation reached the corresponding Wireshark packet. Disabling AI prevented new discovery requests. Deterministic event/finding state remained unchanged.

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

The 21 fixture captures' final release CLI process runtimes had median 85.674 ms and maximum 88.765 ms on this machine. These include EPAN startup, file I/O, extraction, state processing, serialization and process teardown; they are **not** per-packet tap latency or an industrial throughput claim. Exact rows are in `results/benchmark.json`. A 10,000-event unit regression verifies bounded context summarization over all selected observations. The viewer uses Qt models, not one widget per event, and never automatically rescans on every packet selection.

The full-tree tap requirement adds Wireshark dissection work while the viewer is open. Event/transaction/finding limits are explicit; reaching them yields partial-results diagnostics. No claim is made that the current limits support unbounded live captures or every industrial SV rate.

The final endpoint-provenance regression checks all 21 fixtures for nonempty source/destination identity. Exported-PDU MMS uses visible exported-PDU address fields; events lacking endpoint identity are retained but excluded from correlation.
