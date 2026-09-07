// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QByteArray>
#include <QString>
#include <QVector>
#include <memory>
#include <cstdint>

namespace pv
{
using NodeId = int;
struct BitRange {
    uint64_t start = 0, length = 0;
    uint64_t end() const
    {
        return start + length;
    }
    bool operator==(const BitRange&) const = default;
};
struct DataSource {
    QString name;
    QByteArray bytes;
    uint64_t captured = 0, reported = 0;
    bool currentFrame = false;
    QString provenance;
};
struct Field {
    NodeId id = -1, parent = -1, protocolNode = -1;
    int hfId = -1, protocolId = -1, type = 0, source = -1;
    int protocolLayer = 0, totalLayer = 0, depth = 0;
    QString abbreviation, name, description, display, rawValue, typeName, protocol;
    uint64_t start = 0, length = 0, appendixStart = 0, appendixLength = 0, mask = 0;
    unsigned bitOffset = 0, bitSize = 0;
    uint32_t flags = 0;
    bool generated = false, hidden = false, littleEndian = false, bigEndian = false;
    bool protocolGroup = false, structural = false, wireBacked = false, derived = false;
    bool exact = false, clipped = false;
    QVector<BitRange> ranges;
    QString rangeNote;
};
struct PacketModel {
    uint32_t frame = 0;
    uint64_t captured = 0, reported = 0, generation = 0;
    int linkType = -1;
    QVector<DataSource> sources;
    QVector<Field> fields;
    QString diagnostic, protocols;
    double extractionMs = 0;
    const Field* field(NodeId id) const
    {
        return id >= 0 && id < fields.size() ? &fields[id] : nullptr;
    }
};
using Packet = std::shared_ptr<const PacketModel>;
QString validateModel(const PacketModel& model);
}
