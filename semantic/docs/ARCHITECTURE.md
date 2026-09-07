# Stateful Semantic Protocol Analyzer — architecture and API gate

Target: Wireshark 4.7.4 development, upstream
9fc76ca769c9226b3d484cc43e5b62289fab1da3, Qt 6.4.2, GCC 13.3.0,
Ubuntu 24.04.4. This checkout's unmodified build and native UI plugin loading
were already validated before the semantic project. The semantic extension is
a separate UI module; it does not depend on the packet viewer or its geometry.

## Investigated interfaces (2026-09-07)

- epan/tap.h: register_tap_listener("frame"), reset/packet/draw callbacks,
  TL_REQUIRES_PROTO_TREE plus epan_set_always_visible(true), balanced by false
  on viewer destruction. Actual GUI tests established that optimized trees mark
  retained fields hidden and omit required grouping nodes. Full-tree mode is the
  documented API for this case. It costs additional dissection work while open.
  The finite tap filter primes semantic fields and includes frame.number so
  every frame can advance the observed-time watermark.
- epan/funnel.h: funnel_get_funnel_ops()->retap_packets(ops_id) requests the
  initial capture pass, with Wireshark's own progress/cancellation behavior.
  No private MainWindow method, timer redissection, or worker EPAN access.
- ui/plugins/include/plugin_if.h: UI menu registration, goto_frame,
  apply_filter and synchronous capture-file access.
- Current pluginifdemo/build integration matches the existing pinned project.
- Current dissector field registrations in packet-iec104.c, packet-goose.c,
  packet-sv.c, packet-mms.c, packet-mbtcp.c and packet-dnp.c define extraction.
  IEC104 APCI and ASDU are sibling tree nodes. Multiple PDUs and object subtrees
  must be kept distinct; flattening a packet into one dictionary is incorrect.
- Public Qt frame/capture signals supply selection notifications/invalidation.
  At this revision framesSelected often carries visual row indices, despite its
  header comment. Single-frame identity is read via plugin_if_get_frame_data.
  Multiple rows are mapped through the native Qt model's configured Number
  column; the plugin event table is available when that column is absent.
- pinfo.rel_ts is relative to the first frame. rel_cap_ts instead requires
  explicit capture-start metadata and is unavailable for ordinary PCAPs; GUI
  validation caught this distinction. No display reference timestamp is used.

## Data flow

Packet
  -> Wireshark Dissector
  -> Normalized Semantic Event
  -> Deterministic Protocol State Machine
  -> Transaction / Stream / Semantic Window
  -> Deterministic Feature Extraction
  -> Deterministic Finding or Semantic Context
  -> Strict Allowlist Sanitization
  -> Structured JSON
  -> Optional OpenCode Go Model
  -> AI-Generated Explanation or AI-Derived Observation

All dissection data is copied inside the tap callback. Only allowlisted typed
values and local provenance survive. No raw bytes or arbitrary protocol-tree
text enters the normalized model. Protocol modules consume normalized events
and know nothing about Qt widgets, provider APIs or asset JSON syntax.

The event/transaction/finding store has explicit capacity limits and frame/flow
indexes. New events are processed once; reset callbacks rebuild when Wireshark
retaps. Deadlines advance on observed capture timestamps, never wall-clock
absence at a capture boundary. A first response is unresolved/boundary-limited,
not automatically invalid. Timestamp regression is recorded, not silently sorted
into a fictitious capture order. TCP retransmission metadata prevents repeated
semantic operations; application duplicates are kept distinct.

Context construction is deterministic and supports selections, transactions,
flows, devices, protocols, time windows and comparisons. Statistics group by
semantic measurement identity, never mix unrelated IOAs into one average.
Contexts exceeding configured limits are explicitly summarized or rejected.

## AI boundary

Core libraries do not link Qt Network. AI is a separate optional component with
an unchecked enable control, asynchronous requests, cancellation, TLS peer
verification, no redirects, bounded responses and timeouts. Keys come from
OPENCODE_API_KEY or a session-only masked entry, never QSettings or reports.

Model discovery uses https://opencode.ai/zen/go/v1/models. The observed catalog
contains IDs but not API-format metadata. API mapping is resolved from the
current official Go endpoint table; an unknown mapping is disabled, never
inferred from a model's name. Catalog refresh is user-triggered and gated by
AI enablement. Provider documentation: https://opencode.ai/docs/go/ .
This service targets coding-agent traffic; compatibility with semantic-analysis
traffic and authenticated inference require a real provider test, not a claim
based solely on documentation. The live-provider gate was executed using a
session-only key supplied through echo-disabled stdin; see VALIDATION.md. The
key is not retained in the environment or application settings. Offline/mock
tests are reported separately from that live acceptance run.

Outbound summaries are constructed from a schema allowlist. Local endpoint,
publisher and dataset identifiers are pseudonymized; untrusted packet strings,
raw bytes, hidden fields and arbitrary display text are not serialized. The
preview freezes the exact request body before an explicit Send. AI output has
its own store and must reference only evidence in that frozen context. It can
never mutate deterministic findings, severities, transactions or measurements.
