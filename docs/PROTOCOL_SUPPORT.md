# Protocol support

The extractor is generic: it uses the protocol tree for every dissector enabled
in the selected Wireshark build. There is no renderer-side protocol parser.
Build-time optional Wireshark features still govern what can be dissected.

## Executed synthetic fixtures

| Protocol / condition | Fixture scope |
|---|---|
| Ethernet, IPv4, TCP | Source/destination, header fields, SYN and data packets |
| UDP, ARP, ICMP | Basic datagram, ARP request, echo request |
| 802.1Q | VLAN ID and priority/bit layout |
| IPv6 | Fixed header and UDP; intentional checksum expert condition |
| TCP options | MSS, NOP and window-scale option |
| IPv4 options | NOP and end-of-options markers |
| Bit fields | IPv4 nibbles/DF and TCP flags; synthetic unit tests also cover disjoint masks |
| Truncated/malformed/empty | Captured/report difference, invalid IPv4 IHL, zero length |
| TCP reassembly | Two-segment Modbus request, separate reassembled source |
| IPv4 reassembly | Two fragments, UDP in separate reassembled source |
| Modbus/TCP | `mbtcp`, `modbus`: read holding registers request |
| IEC 60870-5-104 | `iec60870_104`, `iec60870_asdu`: I-format single-point ASDU |
| IEC 61850 GOOSE | `goose`: Boolean dataset, including 512-field benchmark |
| IEC 61850 MMS | `mms`: BER identify request in synthetic Exported PDU encapsulation |
| IEC 61850 Sampled Values | `sv`: one ASDU |
| DNP3 | `dnp3`: link-layer reset with valid header CRC |

The smart-grid protocol identifiers and selected abbreviations were checked
against proto_register_protocol and header registration entries in the pinned
Wireshark source. Presence of a dissector is distinct from fixture validation.

## Not explicitly tested

MPLS, nested VLANs, tunnels, repeated encapsulations, IPv6 extension headers,
non-Ethernet physical link types other than Wireshark Upper PDU, IPsec/TLS
plaintext, decompression, live captures, and the broader application behavior
of the protocols above. These may produce generic models through Wireshark,
but no explicit fixture-based correctness claim is made for them.
