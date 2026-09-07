# Limitations

- Validated against one pinned development revision, not a stable UI-plugin ABI.
  Installed 4.2.x and arbitrary 4.6/4.7 binaries are not compatible targets.
- Native Linux/Qt 6.4.2 is the executed platform. Windows and macOS builds and
  GPU drivers are NOT TESTED here. Portable source and instructions are not
  evidence of those platforms working.
- A modeless window is used; the public UI-plugin interface provides no docking
  operation. Reverse selection into native Packet Details/Bytes is not exposed.
  The plugin's inspector and raw view are authoritative for viewer clicks.
- Finer bit occupancy cannot be reconstructed when Wireshark discards it (for
  example split-bit crumb arrays without a preserved mask). Geometry describes
  the reported container in that case; it is not a claim that every container
  bit contributes to the displayed value. Appendix spans are inspector metadata.
- No general mapping of reassembled/transformed bytes back to constituent frames
  is exposed. These sources are kept separate, with no fabricated wire mapping.
- Structural and alias fields fully covered by canonical interpretations have
  no separate solid object; select them in the hierarchy. Dense field labels
  are suppressed; hover or tree selection still exposes copied metadata.
- There are explicit resource limits (see architecture). Very large snapshots
  can be partially omitted with a diagnostic. Extraction and layout occur on
  the GUI thread; the benchmark is bounded, not a real-time guarantee.
- OpenGL 2.1/GLSL 1.20 is required. An unavailable context or shader failure
  leaves a diagnostic and the metadata/byte tools; it does not provide a
  software replacement 3D renderer. Performance depends on Qt's driver backend.
- Tested smart-grid traffic is synthetic and narrow: DNP3 link reset only; MMS
  identify request in Wireshark Upper PDU encapsulation, not an entire OSI
  association. No claim of exhaustive protocol validation is made.
- This plugin does not verify dissector correctness, repair malformed packets,
  validate protocol standards in general, or provide security threat detection.
- The system desktop's QtDBus theme initialization leaks 553 bytes under LSan,
  reproduced with plugins disabled. GTK/ATK initialization without a session
  bus also produced a 56-byte leak. Isolated GUI sanitizer tests pass; the
  ordinary desktop host is not claimed leak-free. See retained reports.
