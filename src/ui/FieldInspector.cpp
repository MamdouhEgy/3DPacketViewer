// SPDX-License-Identifier: GPL-2.0-or-later
#include "FieldInspector.h"
#include <QStringList>
namespace pv
{
QString FieldInspector::describe(const PacketModel& m, const Field& f)
{
    QStringList ranges;
    uint64_t width = 0;
    for (auto r : f.ranges) {
        ranges << QString("[%1, %2)").arg(r.start).arg(r.end());
        width += r.length;
    }
    const auto source
        = f.source >= 0 && f.source < m.sources.size() ? m.sources[f.source].name : "Unavailable";
    return QString(
        "%1 (%2)\nProtocol: %3\n%4\nRaw semantic value: %5\nType: %6; HF ID: %7\nByte offset: %8; length: "
        "%9\nBit-offset metadata: %10; bit-size metadata: %11\nRepresented range bits: %12; MSB-first "
        "ranges: "
        "%13\nMask: 0x%14\nData source: %15\nGenerated: %16; hidden: %17; derived source: %18\nByte order: "
        "%19\nParent: %20; protocol layer: %21; total layer: %22\nAppendix: %23 + %24\n%25\n%26")
        .arg(f.name, f.abbreviation, f.protocol, f.display, f.rawValue, f.typeName)
        .arg(f.hfId)
        .arg(f.start)
        .arg(f.length)
        .arg(f.bitOffset)
        .arg(f.bitSize)
        .arg(width)
        .arg(ranges.join(", "))
        .arg(f.mask, 0, 16)
        .arg(source)
        .arg(f.generated ? "yes" : "no", f.hidden ? "yes" : "no", f.derived ? "yes" : "no",
            f.littleEndian    ? "little"
                : f.bigEndian ? "big"
                              : "unspecified")
        .arg(f.parent)
        .arg(f.protocolLayer)
        .arg(f.totalLayer)
        .arg(f.appendixStart)
        .arg(f.appendixLength)
        .arg(f.rangeNote, f.description);
}
void FieldInspector::showField(const PacketModel& m, const Field* f)
{
    setPlainText(f ? describe(m, *f) : "Select a field in the scene or protocol tree.");
}
}
