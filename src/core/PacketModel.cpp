// SPDX-License-Identifier: GPL-2.0-or-later
#include "PacketModel.h"
namespace pv
{
QString validateModel(const PacketModel& m)
{
    for (int i = 0; i < m.sources.size(); ++i)
        if (m.sources[i].captured != uint64_t(m.sources[i].bytes.size()))
            return "Data source bounds disagree";
    for (int i = 0; i < m.fields.size(); ++i) {
        const auto& f = m.fields[i];
        if (f.id != i || f.parent >= i || f.parent < -1)
            return "Invalid hierarchy";
        if (f.generated && !f.ranges.empty())
            return "Generated field occupies physical bits";
        for (const auto r : f.ranges) {
            if (f.source < 0 || f.source >= m.sources.size())
                return "Invalid source identity";
            const auto bound = m.sources[f.source].captured * 8;
            if (!r.length || r.start > bound || r.length > bound - r.start)
                return "Field outside data source";
        }
    }
    return {};
}
}
