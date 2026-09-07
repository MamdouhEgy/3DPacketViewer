// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "Contracts.h"
#include <QObject>
#include <QNetworkAccessManager>
#include <QPointer>
#include <QNetworkReply>
#include <functional>
namespace sspa
{
class AIProvider : public QObject
{
    Q_OBJECT
public:
    using QObject::QObject;
    virtual void setEnabled(bool) = 0;
    virtual bool enabled() const = 0;
    virtual void setApiKey(QByteArray) = 0;
    virtual bool keyConfigured() const = 0;
    virtual void refreshModels() = 0;
    virtual void send(const PreparedRequest&) = 0;
    virtual void cancel() = 0;
    virtual QVector<Model> models() const = 0;
signals:
    void modelsChanged();
    void completed(QJsonObject result, QJsonObject metadata);
    void failed(QString message);
};
class OpenCodeGoProvider final : public AIProvider
{
    Q_OBJECT
public:
    explicit OpenCodeGoProvider(QObject* parent = nullptr, QNetworkAccessManager* testTransport = nullptr);
    ~OpenCodeGoProvider() override;
    void setEnabled(bool) override;
    bool enabled() const override
    {
        return active;
    }
    void setApiKey(QByteArray) override;
    bool keyConfigured() const override
    {
        return !key.isEmpty();
    }
    void refreshModels() override;
    void send(const PreparedRequest&) override;
    void cancel() override;
    QVector<Model> models() const override
    {
        return catalog;
    }
    quint64 requestCount() const
    {
        return started;
    }
    int timeoutMs = 45000;

private:
    QNetworkAccessManager network;
    QNetworkAccessManager* transport;
    QByteArray key;
    QVector<Model> catalog;
    QVector<QPointer<QNetworkReply>> replies;
    bool active = false;
    quint64 generation = 0, started = 0;
    QString session;
    void request(QUrl, QByteArray, ApiType, int, std::function<void(QByteArray, QString)>);
};
}
