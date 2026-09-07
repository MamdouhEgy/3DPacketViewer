# Assets, topology, policy and semantic contexts

Policies are optional local JSON, schema `1.0`. Load through the viewer or the headless analyzer's third argument. Unknown keys, malformed types, excessive lists and out-of-range numbers are rejected; a rejected configuration does not replace the current one. See `tests/fixtures/policy.json` for a synthetic unexpected-source example.

```json
{
  "schema_version": "1.0",
  "enforce_control_sources": true,
  "transaction_timeout_ms": 5000,
  "sv_counter_modulus": 4000,
  "assets": {
    "192.0.2.1": {
      "name": "Synthetic control center",
      "role": "CONTROL_CENTER",
      "control_source": true,
      "peers": ["192.0.2.2"],
      "protocols": ["IEC104", "MODBUS"]
    },
    "192.0.2.2": {
      "role": "RTU",
      "common_addresses": [2],
      "ioas": [1007]
    }
  }
}
```

Roles: UNKNOWN, CONTROL_CENTER, RTU, PROTECTION_IED, MERGING_UNIT, HMI, ENGINEERING, GATEWAY. Endpoint keys use the decoded IP or MAC representation. Peer lists express allowed direction from that asset. Lists may restrict protocols, publisher IDs, datasets, VLANs, function codes, Common Addresses and IOAs. Missing or empty lists mean no restriction. Control authority is explicit only when `enforce_control_sources` is true. Unknown devices are not malicious by default.

Optional timing values: `expected_interval_ms`, `interval_tolerance_ms`, `expected_sample_rate`; zero disables their checks. The transaction timeout defaults to an implementation observation threshold of 5000 ms, not a universal protocol requirement. The SV counter modulus defaults to unknown (0). Timing settings currently apply across the analyzer, not per-stream profiles: use separate captures/configurations for heterogeneous SV rate profiles. SCL import, topology discovery and semantic unit scaling are not implemented.

## Normalized schema

An event contains schema version, protocol, event type, frame, ordinal/local ID, capture-relative milliseconds, endpoint/role, connection/publisher/object keys, retransmission/reordering/malformed status and a map of typed values. Each value has a nonempty list of field provenance. Derived classifications copy the evidence of the fields used to derive them. Numeric operations reject non-finite values, unsafe integer-to-double conversion and textual lookalikes. Protocol modules do not parse serialized JSON.

Transactions record operation, object, participating events/frames, endpoint roles, transitions, start/end times and completion. Findings are independent evidence-bearing objects. Deterministic exports and AI outputs are separate documents; the former never includes remote output.

## Context selection and statistics

Use the selected semantic event as the anchor for conversation/publisher/protocol/device and time-window modes. Native packet selection supplies current frames; multiple native rows are resolved through the public Qt model's Number column, accounting for sorting and display filters. If that column is unavailable or rows are aggregated, use the plugin's event-table multi-selection. A selected transaction can expand context to its own frames. Partial packet selections do not include a transaction's state or latency derived from unselected events.

Time windows default to five seconds before/after the anchor. Range comparison uses inclusive frame bounds. Entity comparisons use the exact local flow/publisher/device/transaction ID shown in details. Capture summary includes all stored semantic events. Multiple selected transaction rows and event rows are supported. A deterministic context operation runs only on explicit user action; packet arrival does not rescan the capture.

Measurement identity includes protocol, connection, source, publisher, object, Common Address and measurement kind. A feature series never silently combines different IOAs, publishers or command types. Local calculations include adjacent delta, elapsed time, rate per second, mean, median, population variance/stddev, extrema, range, interpolated 5th/95th percentile, mean interval and interval standard deviation. Zero/negative time differences produce no rate. Arithmetic overflow is explicit and represented as null. Identical adjacent values are counted as unchanged observations, not necessarily duplicated packets.

For larger contexts, all selected observations contribute to statistics. At most 500 representative events by default (configurable up to 5000), 256 series and 200 transactions are included. Representative points include endpoints, extrema and the largest adjacent change; this is not a statistical attack detector. Full adjacent-difference arrays are omitted when sampling is necessary. Summarization is labeled; too many series or an oversized request is rejected. The default maximum explicit time window is one hour, request 256 KiB and response 2048 tokens; UI byte/token/event limits are adjustable within bounded ceilings.

Comparison subtracts summary statistics only for identical measurement identities. Different-device/conversation comparisons expose both independently calculated summaries to the analyst/optional model, without claiming signal equivalence. Flow/device/capture contexts provide hierarchical aggregation from events and transactions; no stateful external AI memory is used.
