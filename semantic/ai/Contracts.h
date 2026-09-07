// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "Sanitizer.h"
#include <QUrl>
namespace sspa
{
enum class ApiType { Unknown, Responses, ChatCompletions, Messages };
QString apiName(ApiType);
struct Model {
    QString id;
    ApiType api = ApiType::Unknown;
};
struct PreparedRequest {
    QByteArray body;
    QUrl url;
    QString model, classification, error;
    ApiType api = ApiType::Unknown;
    SanitizedContext context;
    QJsonObject metadata;
};
QVector<Model> parseCatalog(const QByteArray&, QString& error);
QMap<QString, ApiType> parseEndpointTable(const QByteArray&);
PreparedRequest prepareRequest(const Model&, SanitizedContext, QString question, QString classification,
    int maxBytes = 262144, int maxTokens = 2048);
QByteArray responseText(ApiType, const QByteArray&, QString& error);
QJsonObject validateResponse(const QByteArray&, const PreparedRequest&, QString& error);
}
