// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "core/PacketModel.h"
#include <epan/epan_dissect.h>
namespace pv
{
class ProtoTreeExtractor
{
public:
    static Packet extract(epan_dissect_t*, uint32_t frame, uint64_t captured, uint64_t reported, int linkType,
        uint64_t generation);
};
}
