# Privacy boundary, provider contract and threat model

The deterministic core is offline. It has no network dependency, telemetry, analytics, cloud calls, shell execution or AI requirement. Wireshark dissects untrusted traffic. Only explicitly registered semantic fields are copied; raw buffers, credentials, arbitrary display strings, hidden fields and opaque payloads are excluded. Packet contents never become shader code, executable commands or trusted model instructions.

The remote path is a distinct boundary:

```text
Packet
    |
Wireshark Dissector
    |
Normalized Semantic Event
    |
Deterministic Protocol State Machine
    |
Transaction / Stream / Semantic Window
    |
Deterministic Feature Extraction
    |
Deterministic Finding or Semantic Context
    |
Strict Allowlist Sanitization
    |
Structured JSON
    |
Optional OpenCode Go Model
    |
AI-Generated Explanation or AI-Derived Observation
```

## Allowlist

`ai/Sanitizer.cpp` is independent of the extractor allowlist. Outbound event properties have fixed names. Only supported protocol/event enums, fixed role enums, finite allowlisted numeric fields, booleans, frame references, computed statistics and pseudonymized identities are serialized. Endpoint IP/MAC, flow names, dataset/control-block/goID/svID/object identities and dataset fingerprints become request-local tokens. No arbitrary packet string becomes a model instruction. Non-numeric values placed under numeric keys are rejected. Unrecognized properties have no serialization path.

IOAs, Common Addresses, counters, register numbers, timing and measurement values are intentional semantic disclosures. Pseudonymization does not make a semantic request anonymous or non-sensitive. The preview is the control for reviewing exactly those disclosures. The user's typed question is also transmitted and must not contain secrets. Any body containing the configured API key is rejected before transmission. Findings' free-form observed/expected text is local only; remote findings identify rule/category/severity and evidence. No complete unfiltered tree is serialized.

## Credentials and preview

An environment key or masked session-only key is held in process memory and used only for the provider authentication header. QSettings stores a selected model ID only. There is no key file, source constant, report field, diagnostic dump or plaintext fallback. Clearing/replacing/destroying the provider overwrites its retained QByteArray, but ordinary Qt/OS memory management cannot guarantee erasure of every historical copy or exclusion from operating-system crash dumps. Use the host's secure process/coredump policy in sensitive deployments. A key pasted into a conversation should be rotated.

The checkbox is always initially unchecked. When off, discovery and sends fail locally without network activity. Requests use asynchronous Qt Network. Disabling, cancellation, capture reset and key replacement invalidate pending callbacks. Capture changes also invalidate a request prepared in a preview dialog. Requests are not automatically retried or silently switched to another model. AI errors remain in the AI panel, and deterministic state is unchanged.

The modal preview shows the exact UTF-8 JSON body sent, including the task contract and user's question. The destination URL is shown; the credential header is deliberately excluded from display. There is no session-wide automatic-send mode. Deterministic context construction works without enabling AI.

## Dynamic model discovery and adapters

Discovery uses the official `https://opencode.ai/zen/go/v1/models` endpoint. The current response supplies IDs but does not specify API type. The provider resolves each current ID against the endpoint table in the official `https://opencode.ai/docs/go/` page. Unknown/unrecognized mappings remain disabled; there is no guessed default adapter. This HTML dependency is an explicit compatibility risk: a provider layout change may require a parser update. Models themselves are not hardcoded.

Separate request/response transformations support Responses, Chat Completions and Messages. HTTPS endpoints are restricted to the configured provider's exact host and API paths. Redirects are not followed, TLS peer verification is enabled, and authentication is in the appropriate header. Requests identify the analyzer with its own user agent and a stable random session ID; no coding-agent impersonation. The current Go service primarily targets coding-agent use and may reject this application. No attempt is made to bypass service policy.

Public catalog requests carry no key or packet context. Catalog size is limited to 1 MiB/2000 IDs; documentation to 2 MiB; analysis responses to 1 MiB and extracted AI JSON to 128 KiB. The request timer defaults to 45 seconds. Catalog failure, HTTP authentication/rate-limit errors, malformed JSON, oversized responses, timeouts and cancellation do not affect capture or transaction reconstruction. Test transports exercise these paths without using credentials or the network.

## Response validation and reproducibility

AI output must be strict JSON with the requested classification, bounded summary/observations, bounded text and machine-readable evidence frames. Frames must belong to the submitted context. Unknown properties, invented finding IDs, unbounded arrays and missing evidence are rejected. AI output is rendered in a plain-text widget and evidence navigation is built from validated integers. It is never interpreted as HTML, executed or merged into deterministic findings. A model may still produce an incorrect hypothesis: schema validation establishes provenance and structure, not truth.

AI exports contain provider, selected model, API type, timestamp, analyzer/schema/module/preprocessing versions, context type, request size and evidence count. They contain no key. Model nondeterminism means identical requests may produce different prose. Deterministic analysis is reproducible independently. Provider data handling is model-dependent; consult the current official provider policy rather than assuming zero retention.

## Threats and residual risks

Threats include hostile packet labels, oversized trees, invalid numeric metadata, malicious model output, prompt-injection strings, provider errors, capture changes during requests and credential leakage. Controls include deep copying, traversal/depth/allocation bounds, finite-number checks, strict outbound allowlists, tokenized strings, checked response references, generation cancellation and plain-text rendering. Core state stores stop with an explicit partial-results diagnostic at their limits.

The analyzer inherits Wireshark and Qt's own parser/TLS/platform security posture. It is not a sandbox around Wireshark dissectors and cannot prevent vulnerabilities in upstream dissection before its callback. Local report exports intentionally contain sensitive endpoint/provenance information. Application memory can be inspected by sufficiently privileged local processes. No software-level claim can substitute for host access control or an OT deployment review.
