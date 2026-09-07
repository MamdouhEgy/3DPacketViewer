// SPDX-License-Identifier: GPL-2.0-or-later
#include <QtTest>
#include "core/FieldRangeResolver.h"
#include "core/PacketGeometryEngine.h"
#include "core/SelectionController.h"
#include "rendering/CameraController.h"
using namespace pv;
class CoreTests : public QObject
{
    Q_OBJECT
    PacketModel model()
    {
        PacketModel m;
        m.frame = 1;
        m.captured = m.reported = 16;
        m.sources.push_back({ "Frame", QByteArray(16, '\x55'), 16, 16, true, "Current frame" });
        return m;
    }
    Field field(int id = 0, int parent = -1, uint64_t start = 0, uint64_t len = 2)
    {
        Field f;
        f.id = id;
        f.parent = parent;
        f.depth = parent < 0 ? 0 : 1;
        f.source = 0;
        f.start = start;
        f.length = len;
        f.bigEndian = true;
        return f;
    }
private slots:
    void byteRange()
    {
        auto m = model();
        auto f = field();
        FieldRangeResolver::resolve(f, m.sources);
        QCOMPARE(f.ranges, QVector<BitRange>({ { 0, 16 } }));
        QVERIFY(f.wireBacked);
        QVERIFY(f.exact);
    }
    void bits()
    {
        auto m = model();
        auto f = field();
        f.bitOffset = 3;
        f.bitSize = 9;
        FieldRangeResolver::resolve(f, m.sources);
        QCOMPARE(f.ranges, QVector<BitRange>({ { 3, 9 } }));
    }
    void masks_data()
    {
        QTest::addColumn<qulonglong>("mask");
        QTest::addColumn<bool>("little");
        QTest::addColumn<QVector<BitRange>>("ranges");
        QTest::newRow("BE-low") << qulonglong(1) << false << QVector<BitRange> { { 15, 1 } };
        QTest::newRow("LE-low") << qulonglong(1) << true << QVector<BitRange> { { 7, 1 } };
        QTest::newRow("BE-noncontiguous")
            << qulonglong(0x8101) << false << QVector<BitRange> { { 0, 1 }, { 7, 1 }, { 15, 1 } };
        QTest::newRow("LE-noncontiguous")
            << qulonglong(0x8101) << true << QVector<BitRange> { { 7, 2 }, { 15, 1 } };
        QTest::newRow("BE-crossbyte") << qulonglong(0x03c0) << false << QVector<BitRange> { { 6, 4 } };
    }
    void masks()
    {
        QFETCH(qulonglong, mask);
        QFETCH(bool, little);
        QFETCH(QVector<BitRange>, ranges);
        auto m = model();
        auto f = field();
        f.mask = mask;
        f.littleEndian = little;
        f.bigEndian = !little;
        FieldRangeResolver::resolve(f, m.sources);
        QCOMPARE(f.ranges, ranges);
    }
    void maskWithExplicitOffset()
    {
        auto m = model();
        auto f = field();
        f.bigEndian = false;
        f.mask = 0x0fff;
        f.bitOffset = 4;
        f.bitSize = 12;
        FieldRangeResolver::resolve(f, m.sources);
        QCOMPARE(f.ranges, QVector<BitRange>({ { 4, 12 } }));
    }
    void higherProtocolWins()
    {
        auto m = model();
        auto payload = field(0, -1, 0, 16);
        payload.protocolNode = 0;
        auto app = field(1, -1, 0, 2);
        app.protocolNode = 1;
        m.fields = { payload, app };
        for (auto& f : m.fields)
            FieldRangeResolver::resolve(f, m.sources);
        auto g = PacketGeometryEngine::build(m, {});
        QCOMPARE(g.tiles[0].field, 1);
    }
    void generated()
    {
        auto m = model();
        auto f = field();
        f.generated = true;
        FieldRangeResolver::resolve(f, m.sources);
        QVERIFY(f.ranges.empty());
        QVERIFY(!f.wireBacked);
    }
    void sourceIdentity()
    {
        auto m = model();
        m.sources.push_back({ "Reassembled", QByteArray(4, 'a'), 4, 4, false, "Derived" });
        auto f = field();
        f.source = 1;
        FieldRangeResolver::resolve(f, m.sources);
        QVERIFY(f.derived);
        QVERIFY(!f.wireBacked);
        QCOMPARE(f.ranges.size(), 1);
    }
    void unknownSource()
    {
        auto m = model();
        auto f = field();
        f.source = -1;
        FieldRangeResolver::resolve(f, m.sources);
        QVERIFY(f.ranges.empty());
    }
    void truncated()
    {
        auto m = model();
        auto f = field(0, -1, 15, 6);
        FieldRangeResolver::resolve(f, m.sources);
        QVERIFY(f.clipped);
        QVERIFY(!f.exact);
        QCOMPARE(f.ranges, QVector<BitRange>({ { 120, 8 } }));
    }
    void hugeRange()
    {
        auto m = model();
        auto f = field(0, -1, UINT32_MAX, UINT32_MAX);
        FieldRangeResolver::resolve(f, m.sources);
        QVERIFY(f.ranges.empty());
    }
    void hierarchy()
    {
        auto m = model();
        m.fields = { field(), field(1, 0) };
        QVERIFY(validateModel(m).isEmpty());
        m.fields[1].parent = 1;
        QVERIFY(!validateModel(m).isEmpty());
    }
    void noDuplicateOverlap()
    {
        auto m = model();
        auto parent = field(0, -1, 0, 16);
        parent.structural = true;
        auto child = field(1, 0, 1, 3);
        auto alias = child;
        alias.id = 2;
        m.fields = { parent, child, alias };
        for (auto& f : m.fields)
            FieldRangeResolver::resolve(f, m.sources);
        auto g = PacketGeometryEngine::build(m, {});
        uint64_t bits = 0;
        bool childFound = false;
        for (auto t : g.tiles) {
            bits += t.bits.length;
            QVERIFY(t.field != 2);
            childFound |= t.field == 1;
        }
        QCOMPARE(bits, uint64_t(128));
        QVERIFY(childFound);
        QCOMPARE(g.tiles, PacketGeometryEngine::build(m, {}).tiles);
    }
    void hidden()
    {
        auto m = model();
        auto f = field();
        f.hidden = true;
        FieldRangeResolver::resolve(f, m.sources);
        m.fields = { f };
        auto g = PacketGeometryEngine::build(m, {});
        for (auto t : g.tiles)
            QCOMPARE(t.field, -1);
    }
    void wrapping()
    {
        auto m = model();
        auto f = field(0, -1, 3, 4);
        FieldRangeResolver::resolve(f, m.sources);
        m.fields = { f };
        Layout l;
        l.rowBits = 32;
        auto g = PacketGeometryEngine::build(m, l);
        uint64_t bits = 0;
        for (auto t : g.tiles) {
            QVERIFY(t.bits.length <= 32);
            QVERIFY(t.high.x() <= 32);
            if (t.field == 0)
                bits += t.bits.length;
        }
        QCOMPARE(bits, uint64_t(32));
    }
    void presentationInvariants()
    {
        auto m = model();
        auto p = field();
        p.protocolGroup = true;
        p.abbreviation = "ip";
        auto f = field(1, 0);
        f.protocolNode = 0;
        m.fields = { p, f };
        for (auto& x : m.fields)
            FieldRangeResolver::resolve(x, m.sources);
        Layout a, b;
        b.exploded = false;
        auto ga = PacketGeometryEngine::build(m, a), gb = PacketGeometryEngine::build(m, b);
        QCOMPARE(ga.tiles.size(), gb.tiles.size());
        for (int i = 0; i < ga.tiles.size(); ++i) {
            QCOMPARE(ga.tiles[i].bits, gb.tiles[i].bits);
            QCOMPARE(ga.tiles[i].low.x(), gb.tiles[i].low.x());
        }
        QCOMPARE(m.sources[0].bytes, QByteArray(16, '\x55'));
    }
    void camera()
    {
        CameraController c;
        c.reset();
        c.fit({ 0, 0, 0 }, { 64, 20, 10 });
        auto before = c.matrix({ 800, 600 });
        for (int i = 0; i < 10000; ++i)
            c.orbit({ 3, 2 });
        QVERIFY(std::abs(c.rotation.length() - 1) < 1e-5);
        QVERIFY(c.matrix({ 800, 600 }) != before);
        c.zoom(1000);
        QVERIFY(c.distance > 0);
        c.orthographic = true;
        QVERIFY(c.matrix({ 0, 0 }).determinant() != 0);
    }
    void panAndProjection()
    {
        CameraController c;
        c.reset();
        auto center = c.center;
        c.pan({ 10, 20 }, { 800, 600 });
        QVERIFY(center != c.center);
        const auto p = c.matrix({ 800, 600 });
        c.orthographic = true;
        QVERIFY(c.matrix({ 800, 600 }) != p);
    }
    void picking()
    {
        Geometry g;
        g.tiles.push_back({ 7, 0, 0, { 0, 8 }, { -1, -1, -.1f }, { 1, 1, .1f } });
        CameraController c;
        c.fit(g.tiles[0].low, g.tiles[0].high);
        QCOMPARE(SelectionController::pick(g, c.matrix({ 800, 600 }), { 400, 300 }, { 800, 600 }), 0);
        QCOMPARE(g.tiles[0].field, 7);
        QCOMPARE(SelectionController::pick(g, c.matrix({ 800, 600 }), { 0, 0 }, { 800, 600 }), -1);
    }
    void immutableLifetime()
    {
        auto m = std::make_shared<PacketModel>(model());
        Packet copy = m;
        auto next = std::make_shared<PacketModel>(model());
        next->frame = 2;
        m.reset();
        QCOMPARE(copy->frame, 1u);
        QCOMPARE(next->frame, 2u);
        QCOMPARE(copy->sources[0].bytes.size(), 16);
    }
};
QTEST_GUILESS_MAIN(CoreTests)
#include "CoreTests.moc"
