// SPDX-License-Identifier: GPL-2.0-or-later
#include "ai/Provider.h"
#include <QtTest>
#include <QTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <cstring>
using namespace sspa;
class Reply final : public QNetworkReply
{
    QByteArray bytes;
    qint64 cursor = 0;
    bool done = false;

public:
    Reply(const QNetworkRequest& req, int status, QByteArray data, int delay, QObject* parent)
        : QNetworkReply(parent)
        , bytes(std::move(data))
    {
        setRequest(req);
        setUrl(req.url());
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, status);
        open(QIODevice::ReadOnly | QIODevice::Unbuffered);
        if (delay >= 0)
            QTimer::singleShot(delay, this, [this] {
                if (done)
                    return;
                done = true;
                emit readyRead();
                setFinished(true);
                emit finished();
            });
    }
    void abort() override
    {
        if (done)
            return;
        done = true;
        setError(OperationCanceledError, "Cancelled");
        setFinished(true);
        emit finished();
    }
    qint64 bytesAvailable() const override
    {
        return bytes.size() - cursor + QIODevice::bytesAvailable();
    }

protected:
    qint64 readData(char* dest, qint64 max) override
    {
        const auto n = std::min<qint64>(max, bytes.size() - cursor);
        if (n <= 0)
            return -1;
        std::memcpy(dest, bytes.constData() + cursor, size_t(n));
        cursor += n;
        return n;
    }
};
class Network final : public QNetworkAccessManager
{
public:
    struct Response {
        int status = 200;
        QByteArray bytes;
        int delay = 0;
    };
    QVector<Response> responses;
    QVector<QByteArray> bodies;
    QVector<QNetworkRequest> requests;

protected:
    QNetworkReply* createRequest(Operation, const QNetworkRequest& req, QIODevice* data) override
    {
        requests.push_back(req);
        bodies.push_back(data ? data->readAll() : QByteArray());
        auto r = responses.empty() ? Response { 500, {}, 0 } : responses.takeFirst();
        return new Reply(req, r.status, r.bytes, r.delay, this);
    }
};
class NetworkTests : public QObject
{
    Q_OBJECT
    static void catalog(Network& n)
    {
        n.responses.push_back({ 200, R"({"data":[{"id":"future-model"}]})", 0 });
        n.responses.push_back({ 200,
            "<table><tr><td>Future "
            "Model</td><td>future-model</td><td><code>https://opencode.ai/zen/go/v1/chat/"
            "completions</code></td></tr></table>",
            0 });
    }
    static PreparedRequest prepared()
    {
        SanitizedContext c;
        c.evidenceFrames = { 1 };
        c.json = { { "schema_version", "1.0" }, { "event_count", 1 } };
        return prepareRequest({ "future-model", ApiType::ChatCompletions }, c,
            "Explain synthetic differences", "AI_DERIVED_OBSERVATION");
    }
private slots:
    void discovery()
    {
        Network n;
        catalog(n);
        OpenCodeGoProvider p(nullptr, &n);
        QSignalSpy models(&p, &AIProvider::modelsChanged);
        p.setEnabled(true);
        p.refreshModels();
        QTRY_COMPARE(models.count(), 1);
        QCOMPARE(p.models()[0].id, QString("future-model"));
        QCOMPARE(p.models()[0].api, ApiType::ChatCompletions);
        for (const auto& req : n.requests) {
            QVERIFY(!req.hasRawHeader("Authorization"));
            QVERIFY(req.url().scheme() == "https");
        }
    }
    void offAndCancel()
    {
        Network n;
        catalog(n);
        OpenCodeGoProvider p(nullptr, &n);
        p.refreshModels();
        QCOMPARE(n.requests.size(), 0);
        p.setEnabled(true);
        p.refreshModels();
        p.setEnabled(false);
        QTest::qWait(20);
        QCOMPARE(n.requests.size(), 1);
        QVERIFY(p.models().empty());
    }
    void errors_data()
    {
        QTest::addColumn<int>("status");
        QTest::addColumn<QByteArray>("body");
        QTest::addColumn<int>("delay");
        QTest::newRow("authentication") << 401 << QByteArray("do not render body") << 0;
        QTest::newRow("rate-limit") << 429 << QByteArray("private server diagnostics") << 0;
        QTest::newRow("unavailable") << 503 << QByteArray() << 0;
        QTest::newRow("redirect") << 302 << QByteArray() << 0;
        QTest::newRow("invalid-json") << 200 << QByteArray("not JSON") << 0;
        QTest::newRow("oversized") << 200 << QByteArray(1048577, 'x') << 0;
        QTest::newRow("timeout") << 200 << QByteArray() << -1;
        QTest::newRow("network") << 0 << QByteArray() << 0;
    }
    void errors()
    {
        QFETCH(int, status);
        QFETCH(QByteArray, body);
        QFETCH(int, delay);
        Network n;
        catalog(n);
        OpenCodeGoProvider p(nullptr, &n);
        p.timeoutMs = 30;
        p.setEnabled(true);
        p.setApiKey("test-credential-do-not-log");
        QSignalSpy models(&p, &AIProvider::modelsChanged);
        p.refreshModels();
        QTRY_COMPARE(models.count(), 1);
        n.responses.push_back({ status, body, delay });
        QSignalSpy errors(&p, &AIProvider::failed);
        QSignalSpy completed(&p, &AIProvider::completed);
        auto r = prepared();
        p.send(r);
        QTRY_COMPARE(errors.count(), 1);
        QCOMPARE(completed.count(), 0);
        const auto message = errors.front().front().toString();
        QVERIFY(!message.contains("test-credential"));
        QVERIFY(!message.contains("private server"));
        QCOMPARE(n.bodies.back(), r.body);
        QVERIFY(!r.body.contains("test-credential"));
    }
    void modelDisappears()
    {
        Network n;
        catalog(n);
        OpenCodeGoProvider p(nullptr, &n);
        p.setEnabled(true);
        QSignalSpy models(&p, &AIProvider::modelsChanged);
        p.refreshModels();
        QTRY_COMPARE(models.count(), 1);
        auto r = prepared();
        r.model = "removed-model";
        QSignalSpy errors(&p, &AIProvider::failed);
        p.send(r);
        QCOMPARE(errors.count(), 1);
        QCOMPARE(n.requests.size(), 2);
    }
    void malformedCatalog()
    {
        Network n;
        n.responses.push_back({ 200, "{\"data\":[null]}", 0 });
        OpenCodeGoProvider p(nullptr, &n);
        p.setEnabled(true);
        QSignalSpy errors(&p, &AIProvider::failed);
        p.refreshModels();
        QTRY_COMPARE(errors.count(), 1);
        QVERIFY(p.models().empty());
    }
    void secretEchoRejected()
    {
        Network n;
        catalog(n);
        OpenCodeGoProvider p(nullptr, &n);
        p.setEnabled(true);
        p.setApiKey("test-credential-do-not-log");
        QSignalSpy models(&p, &AIProvider::modelsChanged);
        p.refreshModels();
        QTRY_COMPARE(models.count(), 1);
        n.responses.push_back({ 200, "test-credential-do-not-log", 0 });
        QSignalSpy errors(&p, &AIProvider::failed);
        p.send(prepared());
        QTRY_COMPARE(errors.count(), 1);
        QVERIFY(!errors.front().front().toString().contains("test-credential"));
    }
};
QTEST_GUILESS_MAIN(NetworkTests)
#include "NetworkTests.moc"
