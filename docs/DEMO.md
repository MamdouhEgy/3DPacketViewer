# R-GOOSE demonstration

The 60-second recording demonstrates the actual native Wireshark workflow using
`Routable_GOOSE.pcap`. It is silent, captioned, H.264 MP4, 1920×1080 at 30 fps.
The API key is not displayed. Provider waiting time is shortened in the edit.

https://github.com/user-attachments/assets/9ee6e2f7-3caa-4f56-9b3f-5ec8f9484b0d

| Video time | Action |
|---|---|
| 00:00–00:07 | Open the R-GOOSE capture |
| 00:07–00:18 | Rotate, zoom and explode the 3D protocol stack |
| 00:18–00:26 | Select stNum and inspect source bytes and represented bits |
| 00:26–00:34 | Examine deterministic publication events and semantic context |
| 00:34–00:42 | Select Luna, review the sanitized request and send it |
| 00:42–00:51 | Read the real, explicitly labeled AI-derived observation |
| 00:51–00:57 | Navigate to contributing frame 12 in Wireshark |
| 00:57–01:00 | Disable AI while retaining deterministic analysis |

## What the example establishes

The selected frame's `goose.stNum` value is 4275, located at source byte 171
(`0xAB`) in a two-byte container. The map represents those 16 captured bits; it
does not infer width from the displayed decimal value.

The capture yields 77 normalized semantic events and 11 R-GOOSE publication
observations. These are not 77 independent packets or 11 request-response
transactions. Zero emitted deterministic findings is not a security verdict.

The example values were also checked against the pinned tshark dissector:

| Frame | stNum | sqNum |
|---|---|---|
| 1 | 4275 | 4 |
| 4 | 4275 | 5 |
| 10 | 4275 | 8 |
| 12 | 4276 | 0 |

The observations show repeated publication within a state sequence, followed by
a changed stNum and reset sqNum. The capture alone does not establish the
operational cause. The event's transport `retransmission` marker is not a count
of repeated GOOSE publications.

The recorded response came from dynamically discovered `gpt-5.6-luna` through
OpenCode Go's Responses interface. It references frames 1, 10 and 12; navigation
to frame 12 was checked against Wireshark's current-frame state. This is one
executed provider interaction, not a guarantee of future model availability or
response wording.

## Boundaries

Geometry is derived from Wireshark dissection metadata; layer spacing and camera
motion are presentation. Generated fields do not become physical bytes.

R-GOOSE signature/HMAC verification, key management and authenticated replay
protection are outside scope. Signal names, engineering units, malicious intent
and signature validity are not inferred from this demonstration.

Only the reviewed, allowlisted semantic JSON was submitted to the AI provider.
The video itself displays capture fields and byte views and should be treated as
an analysis artifact, not a sanitized AI request. Its GitHub attachment inherits
the private repository's access requirements. The capture is not included as a
downloadable fixture; automated fixtures remain synthetic.

See [scientific validity](SCIENTIFIC_VALIDITY.md),
[semantic protocol scope](../semantic/docs/PROTOCOLS.md) and
[privacy](../semantic/docs/PRIVACY.md).
