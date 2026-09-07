// SPDX-License-Identifier: GPL-2.0-or-later
#include "PacketGeometryEngine.h"
#include <QElapsedTimer>
#include <algorithm>
#include <map>
#include <set>
namespace pv
{
Geometry PacketGeometryEngine::build(const PacketModel& m, const Layout& layout)
{
    QElapsedTimer timer;
    timer.start();
    Geometry g;
    if (layout.source < 0 || layout.source >= m.sources.size())
        return g;
    if (layout.rowBits != 32 && layout.rowBits != 64 && layout.rowBits != 128) {
        g.diagnostic = "Unsupported bit-row width";
        return g;
    }
    // Sweep endpoints: later protocol interpretation, then deepest field, then tree order.
    // One canonical owner per source bit, globally, even across protocol interpretations.
    struct Event {
        uint64_t bit;
        int field;
        bool start;
    };
    QVector<Event> events;
    for (const auto& f : m.fields) {
        if (f.source != layout.source || f.generated || f.hidden || f.protocolGroup)
            continue;
        for (auto r : f.ranges) {
            events.push_back({ r.start, f.id, true });
            events.push_back({ r.end(), f.id, false });
        }
    }
    std::sort(events.begin(), events.end(), [](const auto& a, const auto& b) { return a.bit < b.bit; });
    auto order = [&](int a, int b) {
        if (m.fields[a].protocolNode != m.fields[b].protocolNode)
            return m.fields[a].protocolNode > m.fields[b].protocolNode;
        if (m.fields[a].depth != m.fields[b].depth)
            return m.fields[a].depth > m.fields[b].depth;
        return a < b;
    };
    std::set<int, decltype(order)> active(order);
    std::map<int, int> layers;
    for (const auto& f : m.fields)
        if (f.protocolGroup && f.abbreviation != "frame")
            layers.emplace(f.id, int(layers.size()));
    const uint64_t end = m.sources[layout.source].captured * 8;
    uint64_t pos = 0;
    qsizetype ei = 0;
    auto append = [&](uint64_t begin, uint64_t finish, int id) {
        int layer = id < 0 ? 0 : layers[m.fields[id].protocolNode];
        while (begin < finish) {
            if (g.tiles.size() >= 200000) {
                g.diagnostic = "Geometry limit reached (200000 tiles); remaining ranges omitted";
                return;
            }
            const auto count = std::min<uint64_t>(finish - begin, layout.rowBits - begin % layout.rowBits);
            const float x = float(begin % layout.rowBits), y = -float(begin / layout.rowBits) * 1.4f;
            const float z = layout.wireView
                ? 0
                : layer * (layout.exploded ? std::clamp(layout.spacing, 0.2f, 20.0f) : 0.22f);
            g.tiles.push_back({ id, layer, layout.source, { begin, count }, { x, y, z },
                { x + float(count), y + 1, z + 0.16f } });
            begin += count;
        }
    };
    while (pos < end) {
        while (ei < events.size() && events[ei].bit <= pos) {
            if (events[ei].start)
                active.insert(events[ei].field);
            else
                active.erase(events[ei].field);
            ++ei;
        }
        const auto next = ei < events.size() ? std::min(end, events[ei].bit) : end;
        append(pos, next, active.empty() ? -1 : *active.begin());
        if (!g.diagnostic.isEmpty())
            break;
        pos = next;
    }
    if (!g.tiles.empty()) {
        g.low = g.tiles.front().low;
        g.high = g.tiles.front().high;
        for (const auto& t : g.tiles)
            for (int axis = 0; axis < 3; ++axis) {
                g.low[axis] = std::min(g.low[axis], t.low[axis]);
                g.high[axis] = std::max(g.high[axis], t.high[axis]);
            }
    }
    g.buildMs = timer.nsecsElapsed() / 1e6;
    return g;
}
}
