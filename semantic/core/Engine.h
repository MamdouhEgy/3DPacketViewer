// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "Model.h"
#include "assets/Policy.h"
#include <QHash>
#include <memory>
#include <queue>
#include <map>
namespace sspa
{
struct Settings {
    double timeoutMs = 5000, intervalMs = 0, intervalToleranceMs = 0;
    qint64 svModulus = 0, sampleRate = 0;
};
class Engine;
class ProtocolAnalyzer
{
public:
    virtual ~ProtocolAnalyzer() = default;
    virtual void consume(const Event&, Engine&) = 0;
};
std::unique_ptr<ProtocolAnalyzer> makeIec104();
std::unique_ptr<ProtocolAnalyzer> makeGoose();
std::unique_ptr<ProtocolAnalyzer> makeSv();
std::unique_ptr<ProtocolAnalyzer> makeMms();
std::unique_ptr<ProtocolAnalyzer> makeModbus();
std::unique_ptr<ProtocolAnalyzer> makeDnp3();
class Engine
{
public:
    explicit Engine(Policy = {});
    void reset();
    bool ingest(Event);
    void observeFrame(quint32 frame, double timeMs);
    int begin(const Event&, const QString& operation, bool startedHere = true);
    void move(int transaction, const Event&, const QString& state, const QString& expected = {});
    void complete(int transaction, const Event&, const QString& state = "COMPLETED");
    void deadline(int transaction);
    void finding(const Event&, QString rule, QString category, QString expected, QString observed,
        QString explanation, QString basis, QVector<quint32> otherFrames = {}, QString severity = "NOTICE");
    QVector<Transaction> snapshotTransactions(bool captureBoundary) const;
    const Event* event(const QString& id) const;
    QVector<Event> events;
    QVector<Transaction> transactions;
    QVector<Finding> findings;
    QHash<quint32, QVector<int>> byFrame;
    QHash<QString, QVector<int>> byFlow;
    Policy policy;
    Settings settings;
    QString diagnostic;
    int maxEvents = 200000, maxTransactions = 50000, maxFindings = 50000;
    quint32 lastFrame = 0;
    double watermarkMs = 0;
    quint64 duplicateTapEvents = 0, retransmissions = 0;

private:
    struct Deadline {
        double observedTime;
        int transaction;
        QString state;
        bool operator>(const Deadline& o) const
        {
            return observedTime > o.observedTime;
        }
    };
    QHash<QString, int> eventIndex;
    std::map<QString, std::unique_ptr<ProtocolAnalyzer>> modules;
    std::priority_queue<Deadline, std::vector<Deadline>, std::greater<Deadline>> deadlines;
};
}
