// SPDX-License-Identifier: GPL-2.0-or-later
#include "Provider.h"
#include <QTimer>
#include <QUuid>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QJsonDocument>
namespace sspa
{
OpenCodeGoProvider::OpenCodeGoProvider(QObject* parent, QNetworkAccessManager* testTransport)
    : AIProvider(parent)
    , network(this)
    , transport(testTransport ? testTransport : &network)
    , key(qgetenv("OPENCODE_API_KEY"))
    , session(QUuid::createUuid().toString(QUuid::WithoutBraces))
{
}
OpenCodeGoProvider::~OpenCodeGoProvider()
{
    cancel();
    key.fill('\0');
}
void OpenCodeGoProvider::setApiKey(QByteArray value)
{
    cancel();
    key.fill('\0');
    key = std::move(value);
}
void OpenCodeGoProvider::setEnabled(bool value)
{
    if (active == value)
        return;
    active = value;
    if (!active)
        cancel();
}
void OpenCodeGoProvider::cancel()
{
    ++generation;
    const auto pending = replies;
    replies.clear();
    for (auto reply : pending)
        if (reply)
            reply->abort();
}
void OpenCodeGoProvider::request(
    QUrl url, QByteArray body, ApiType api, int maxBytes, std::function<void(QByteArray, QString)> done)
{
    if (!active) {
        done({}, "AI is disabled; no request was sent");
        return;
    }
    if (url.scheme() != "https" || url.host() != "opencode.ai" || url.port(-1) != -1
        || !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment()) {
        done({}, "Provider URL rejected");
        return;
    }
    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setHeader(QNetworkRequest::UserAgentHeader, "StatefulSemanticProtocolAnalyzer/0.1.0");
    request.setRawHeader("x-opencode-session", session.toUtf8());
    request.setTransferTimeout(timeoutMs);
    auto ssl = QSslConfiguration::defaultConfiguration();
    ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);
    request.setSslConfiguration(ssl);
    if (!body.isEmpty()) {
        if (key.isEmpty()) {
            done({}, "API key is not configured");
            return;
        }
        if (body.contains(key)) {
            done({}, "Request rejected: credential content must not be transmitted as semantic data");
            return;
        }
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        if (api == ApiType::Messages) {
            request.setRawHeader("x-api-key", key);
            request.setRawHeader("anthropic-version", "2023-06-01");
        } else
            request.setRawHeader("Authorization", "Bearer " + key);
    }
    auto* reply = body.isEmpty() ? transport->get(request) : transport->post(request, body);
    ++started;
    replies.push_back(reply);
    reply->setReadBufferSize(maxBytes + 1);
    struct State {
        QByteArray bytes;
        QString error;
    };
    auto state = std::make_shared<State>();
    auto* timer = new QTimer(reply);
    timer->setSingleShot(true);
    timer->start(timeoutMs);
    const auto epoch = generation;
    connect(timer, &QTimer::timeout, reply, [reply, state] {
        state->error = "AI request timed out";
        reply->abort();
    });
    connect(reply, &QNetworkReply::readyRead, reply, [reply, state, maxBytes] {
        state->bytes += reply->readAll();
        if (state->bytes.size() > maxBytes) {
            state->bytes.clear();
            state->error = "Provider response exceeded size limit";
            reply->abort();
        }
    });
    connect(reply, &QNetworkReply::finished, this,
        [this, reply, state, timer, epoch, maxBytes, done = std::move(done)] {
            timer->stop();
            replies.removeAll(reply);
            state->bytes += reply->readAll();
            const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            QString error = state->error;
            if (state->bytes.size() > maxBytes)
                error = "Provider response exceeded size limit";
            else if (status != 200 && error.isEmpty())
                error = status
                    ? QString("Provider HTTP %1; response body withheld").arg(status)
                    : "Provider connection failed (network or TLS); deterministic analysis is unaffected";
            else if (reply->error() != QNetworkReply::NoError && error.isEmpty())
                error = "Provider transport failed; deterministic analysis is unaffected";
            if (!key.isEmpty() && state->bytes.contains(key))
                error = "Provider response contained credential material and was rejected";
            reply->deleteLater();
            if (epoch != generation || !active)
                return;
            done(error.isEmpty() ? state->bytes : QByteArray(), error);
        });
}
void OpenCodeGoProvider::refreshModels()
{
    if (!active) {
        emit failed("Enable AI Explanation / Analysis before model discovery; no network request was made");
        return;
    }
    request(QUrl("https://opencode.ai/zen/go/v1/models"), {}, ApiType::Unknown, 1048576,
        [this](QByteArray bytes, QString error) {
            if (!error.isEmpty()) {
                emit failed(error);
                return;
            }
            auto found = parseCatalog(bytes, error);
            if (!error.isEmpty()) {
                emit failed(error);
                return;
            }
            request(QUrl("https://opencode.ai/docs/go/"), {}, ApiType::Unknown, 2097152,
                [this, found](QByteArray html, QString problem) mutable {
                    if (!problem.isEmpty()) {
                        catalog = found;
                        emit modelsChanged();
                        emit failed("Models loaded, but API metadata could not be verified; sending is "
                                    "disabled for unmapped models");
                        return;
                    }
                    const auto table = parseEndpointTable(html);
                    for (auto& model : found)
                        model.api = table.value(model.id, ApiType::Unknown);
                    catalog = found;
                    emit modelsChanged();
                    if (table.empty())
                        emit failed("Official endpoint metadata was not recognized; unknown adapters remain "
                                    "disabled");
                });
        });
}
void OpenCodeGoProvider::send(const PreparedRequest& prepared)
{
    if (!active) {
        emit failed("AI is disabled; no request was sent");
        return;
    }
    if (!prepared.error.isEmpty() || prepared.body.isEmpty()) {
        emit failed("No valid prepared AI request");
        return;
    }
    bool available = false;
    for (const auto& model : catalog)
        available |= model.id == prepared.model && model.api == prepared.api && model.api != ApiType::Unknown;
    if (!available) {
        emit failed("Model is absent or API metadata changed; refresh and prepare a new request");
        return;
    }
    if (prepared.url != QUrl("https://opencode.ai/zen/go/v1/" + apiName(prepared.api))
        || prepared.body.size() > 2097152) {
        emit failed("Prepared request endpoint or size rejected");
        return;
    }
    request(
        prepared.url, prepared.body, prepared.api, 1048576, [this, prepared](QByteArray body, QString error) {
            if (!error.isEmpty()) {
                emit failed(error);
                return;
            }
            auto text = responseText(prepared.api, body, error);
            if (!error.isEmpty()) {
                emit failed(error);
                return;
            }
            auto output = validateResponse(text, prepared, error);
            if (!error.isEmpty()) {
                emit failed(error);
                return;
            }
            emit completed(output, prepared.metadata);
        });
}
}
