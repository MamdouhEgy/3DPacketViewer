# Scientific interpretation

The source of semantics is the pinned Wireshark dissection, not a second parser.
This visualization reports Wireshark metadata; it is not a protocol-standard
conformance oracle. Hand-constructed ground truth and tshark agreement are
separate validation methods.

## Aligned byte-and-bit map

The default view uses source-relative byte rows, increasing left to right then
top to bottom. Within each byte, bit labels run from 7 down to 0 (MSB first).
Every represented bit has equal horizontal width; row height is fixed and has
no quantitative meaning. Changing the wrapping width or window size changes
presentation only. Bit digits are omitted when too narrow to read, never
replaced by invented values. Color identifies protocol categories; the focus
control dims other fields without dropping or moving their bits.

The black selection outline and yellow binary highlights use the field's full
resolved ranges, including ranges belonging to structural parents or aliases.
This is an overlay, not additional packet occupancy. A partial mask highlights
only its resolved bits. Display text never determines rectangle width. The
byte-container length in the explanation is distinct from represented bit count.

## Spatial meaning of the optional 3D stack

Let b be a source-relative MSB-first bit index, and W the row width (32, 64,
or 128). X = b mod W. Row = floor(b/W). Y = -1.4 × Row. A contiguous span
occupies exactly one X unit per represented bit, split at row boundaries.
Each box has planar height 1 and thickness 0.16. Therefore summed canonical
planar area in model coordinates equals represented source bits. Row pitch,
height, thickness, gaps and units are presentation conventions, not lengths
in physical space. Z = protocol display layer × chosen spacing when exploded;
collapsed spacing is 0.22. Wire mode uses Z=0. Protocol order is the order in
Wireshark's tree, not a claim that sibling protocols form a physical laminate.

Colors are categorical, with an Okabe–Ito palette. White selection also has
an outline. Gray marks unmapped source bits. Camera zoom, rotation, pan and
projection affect screen projection only. Screen area under perspective is not
quantitative. **Neither box volume nor Z position measures packet size, field
value, timing, importance, or physical transmission position.**

## Field widths and masks

Byte start/length, explicit bit offset/size, and header masks come directly
from field_info/hfinfo. Width is never estimated from text. A zero bit-size
means the reported byte range according to proto.h. Masks are enumerated one
set bit at a time; adjacent occupied bits merge, disjoint runs remain disjoint.
Little-endian significance is mapped byte by byte into MSB-first coordinates.
The recorded FI bit offset is preserved even when it is a registered-container
offset (e.g. TCP flag metadata); resolved bit spans separately express actual
source coordinates. A mask with no endian flag can use Wireshark's explicit
MSB-first offset/size; if neither establishes the mapping, no geometry is made.

Bounds clipping never fabricates missing bytes. Captured and reported lengths
are distinct. Exactness means fidelity to available Wireshark range metadata,
not proof that the dissector describes every semantic bit. Appendix ranges are
reported separately; they are not silently appended to a contiguous main range.

Some Wireshark APIs lose finer information before the protocol tree is exposed.
In particular, proto_tree_add_split_bits_item_ret_val does not preserve its
crumb array as field_info metadata. Such a field's byte container can be
reported, but absent a registered mask or explicit span the plugin cannot
recover those crumbs. It never parses a displayed bitmap to guess them. This
is a limit of the upstream metadata, not a claim of universal bit-level
coverage. No protocol-specific layout is substituted to conceal this limit.

## Overlap policy

Canonical wire-layout geometry partitions each copied source exactly once.
The order of preference is later protocol interpretation, deeper tree node,
then earlier node ID. Parent and alias ranges do not add another copy of bytes.
A parent can cover the residual part of its reported range not assigned to a
more specific interpretation. All overlapping alternatives remain selectable
in the tree, with their complete reported ranges in the inspector and byte view.
A field whose range is fully superseded has no separate clickable box.

This policy is deterministic, not a new claim about which interpretation is
semantically superior. It prevents TCP payload aliases from obscuring the
higher-layer dissection and prevents total displayed occupancy from exceeding
the source length. Uncovered bits are explicitly “Unmapped wire region.”
Only Wireshark's named payload fields are called payload.

## Generated and additional-source fields

FI_GENERATED fields occupy zero wire-layout positions regardless of their
reported start/length. They are labeled [G] in the tree, optional via G, and
identified as having no direct wire range. Hidden fields remain annotated in
the tree but are excluded from canonical geometry.

Each Wireshark data source is a separate coordinate space and byte array.
Additional buffers are marked [D] and described using Wireshark's source name.
A reassembled field can have an exact range within the reassembled buffer while
having **no contiguous range in the selected frame**. Original-frame bytes are
never highlighted for it. No assumptions about encryption, compression or
reassembly are made from numerical offsets alone. The public tree does not
expose a general constituent-frame mapping, so the plugin does not invent one.
