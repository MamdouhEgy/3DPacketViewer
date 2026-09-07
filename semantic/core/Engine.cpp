// SPDX-License-Identifier: GPL-2.0-or-later
#include "Engine.h"
#include <cmath>
namespace sspa
{
Engine::Engine(Policy p)
    : policy(std::move(p))
{
    reset();
}
void Engine::reset()
{
    events.clear();
    transactions.clear();
    findings.clear();
    byFrame.clear();
    byFlow.clear();
    eventIndex.clear();
    diagnostic.clear();
    lastFrame = 0;
    watermarkMs = 0;
    duplicateTapEvents = retransmissions = 0;
    deadlines = {};
    modules.clear();
    settings = { policy.transactionTimeoutMs, policy.expectedIntervalMs, policy.intervalToleranceMs,
        policy.svCounterModulus, policy.expectedSampleRate };
    modules.emplace("IEC104", makeIec104());
    modules.emplace("GOOSE", makeGoose());
    modules.emplace("SV", makeSv());
    modules.emplace("MMS", makeMms());
    modules.emplace("MODBUS", makeModbus());
    modules.emplace("DNP3", makeDnp3());
}
const Event* Engine::event(const QString& id) const
{
    const auto it = eventIndex.constFind(id);
    return it == eventIndex.cend() ? nullptr : &events[*it];
}
bool Engine::ingest(Event e)
{
    if (e.frame == 0 || !std::isfinite(e.timeMs) || !modules.contains(e.protocol))
        return false;
    if (e.id.isEmpty())
        e.id = QString("%1:%2:%3").arg(e.protocol).arg(e.frame).arg(e.ordinal);
    if (eventIndex.contains(e.id)) {
        ++duplicateTapEvents;
        return false;
    }
    if (events.size() >= maxEvents || transactions.size() >= maxTransactions
        || findings.size() >= maxFindings) {
        diagnostic = "Analysis capacity reached; remaining events omitted. Results are partial. Narrow the "
                     "capture and reanalyze.";
        return false;
    }
    e.sourceRole = policy.role(e.source);
    e.destinationRole = policy.role(e.destination);
    observeFrame(e.frame, e.timeMs);
    e.reordered |= e.timeMs < watermarkMs;
    const int position = events.size();
    events.push_back(std::move(e));
    const auto& current = events.back();
    eventIndex.insert(current.id, position);
    byFrame[current.frame].push_back(position);
    byFlow[current.flow].push_back(position);
    for (auto f : policy.evaluate(current)) {
        if (findings.size() >= maxFindings) {
            diagnostic = "Finding capacity reached; results are partial.";
            break;
        }
        f.id = f.rule + ":" + current.id;
        findings.push_back(std::move(f));
    }
    if (current.retransmission) {
        ++retransmissions;
        return true;
    }
    if (current.reordered) {
        finding(current, "CAPTURE_ORDER_UNCERTAIN", "CAPTURE_LIMITATION",
            "Monotonic observed capture timestamps", "Timestamp regression or TCP out-of-order indication",
            "Sequence conclusions for this event are unresolved; capture order may differ from protocol "
            "delivery order.",
            "Implementation observation; no inferred network fault");
    }
    if (current.malformed) {
        finding(current, "DISSECTION_MALFORMED", "MALFORMED", "Usable decoded protocol fields",
            "Wireshark marked malformed content",
            "Wireshark reported malformed content. Transaction interpretation is unresolved.",
            "Wireshark expert dissection result");
        return true;
    }
    if (current.source.isEmpty() || current.destination.isEmpty()) {
        finding(current, "ENDPOINT_IDENTITY_UNRESOLVED", "CAPTURE_LIMITATION",
            "Decoded source and destination identity", "One or both endpoints are unavailable",
            "Cross-packet correlation is omitted to avoid joining unrelated unidentified endpoints.",
            "Conservative analyzer correlation policy");
        return true;
    }
    modules.at(current.protocol)->consume(current, *this);
    return true;
}
int Engine::begin(const Event& e, const QString& operation, bool startedHere)
{
    if (transactions.size() >= maxTransactions)
        return -1;
    Transaction t;
    t.id = e.protocol + "-TX-" + QString::number(transactions.size() + 1);
    t.protocol = e.protocol;
    t.flow = e.flow;
    t.source = e.source;
    t.destination = e.destination;
    t.sourceRole = e.sourceRole;
    t.destinationRole = e.destinationRole;
    t.operation = operation;
    t.object = e.object;
    t.startMs = t.endMs = e.timeMs;
    t.startedHere = startedHere;
    transactions.push_back(t);
    return transactions.size() - 1;
}
void Engine::move(int id, const Event& e, const QString& state, const QString& expected)
{
    if (id < 0 || id >= transactions.size())
        return;
    transition(transactions[id], e, state, expected);
}
void Engine::complete(int id, const Event& e, const QString& state)
{
    if (id < 0 || id >= transactions.size())
        return;
    move(id, e, state);
    auto& t = transactions[id];
    t.completion = t.startedHere ? "COMPLETE" : "INCOMPLETE_CAPTURE_BOUNDARY";
}
void Engine::deadline(int id)
{
    if (id >= 0 && id < transactions.size())
        deadlines.push({ transactions[id].endMs + settings.timeoutMs, id, transactions[id].state });
}
void Engine::observeFrame(quint32 frame, double observedTime)
{
    if (!std::isfinite(observedTime) || frame < lastFrame)
        return;
    lastFrame = frame;
    watermarkMs = std::max(watermarkMs, observedTime);
    while (!deadlines.empty() && deadlines.top().observedTime < watermarkMs) {
        const auto d = deadlines.top();
        deadlines.pop();
        auto& t = transactions[d.transaction];
        if (t.completion != "OPEN" || t.state != d.state || t.events.empty()
            || d.observedTime != t.endMs + settings.timeoutMs)
            continue;
        t.completion = "INCOMPLETE_UNKNOWN";
        const auto* e = event(t.events.back());
        if (!e)
            continue;
        const auto expected = t.transitions.empty() ? QString("response") : t.transitions.back().expected;
        const auto previousCount = findings.size();
        finding(*e, t.protocol + "_MISSING_" + (expected.isEmpty() ? "RESPONSE" : expected), "TIMING_ANOMALY",
            QString("%1 within configured %2 ms").arg(expected).arg(settings.timeoutMs),
            QString("No matching transition before observed frame %1").arg(frame),
            "A configured response deadline elapsed within the observed capture. Packet loss, capture gaps, "
            "unobserved paths, device delay or an incomplete operation are possible; this does not establish "
            "an attack.",
            "Configured transaction_timeout_ms; observation watermark, not wall-clock inference", { frame },
            "WARNING");
        if (findings.size() > previousCount)
            t.findings.push_back(findings.back().id);
    }
}
void Engine::finding(const Event& e, QString rule, QString category, QString expected, QString observed,
    QString explanation, QString basis, QVector<quint32> frames, QString severity)
{
    if (findings.size() >= maxFindings) {
        diagnostic = "Finding limit reached; report is partial.";
        return;
    }
    if (!frames.contains(e.frame))
        frames.push_back(e.frame);
    Finding f;
    f.id = rule + ":" + e.id + ":" + QString::number(findings.size());
    f.rule = rule;
    f.protocol = e.protocol;
    f.category = category;
    f.severity = severity;
    f.expected = expected;
    f.observed = observed;
    f.explanation = explanation;
    f.basis = basis;
    f.frames = frames;
    for (const auto& v : e.values)
        f.evidence += v.evidence;
    findings.push_back(std::move(f));
}
QVector<Transaction> Engine::snapshotTransactions(bool boundary) const
{
    auto result = transactions;
    if (boundary)
        for (auto& t : result)
            if (t.completion == "OPEN")
                t.completion = "INCOMPLETE_CAPTURE_BOUNDARY";
    return result;
}
}
