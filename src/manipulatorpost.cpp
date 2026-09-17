#include "manipulator.h"
#include "jsonobjectyinjectionvector.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QLoggingCategory>
#include <QMessageLogger>
#include <QUrlQuery>

// gui.exe:0x140112A60 (postParameters).
void Manipulator::postParameters(const NetworkResponsePtr &reply)
{
    const QByteArray payload = reply->request.attribute(QNetworkRequest::Attribute(1003)).toByteArray();
    if (payload.isNull())
        return;

    const QByteArray contentType =
        reply->request.rawHeader("Content-Type").toLower();

    bool isJson = payload.startsWith('{');
    if (!isJson)
        isJson = contentType.endsWith("/json");

    bool isXml = contentType.endsWith("/xml");
    if (!isXml)
        isXml = payload.left(10).toLower().trimmed().startsWith("<?xml");

    if (isXml)
    {
        eventTriggered(Event{1024, QVariant(), 0}, reply, nullptr);
    }
    else if (isJson)
    {
        eventTriggered(Event{256, QVariant(), 0}, reply, nullptr);
        jsonParameters(payload, reply);
    }
    else
    {
        QUrlQuery query(QString::fromUtf8(payload));
        queryParameters(query, reply, true, query.queryItems());
    }
}
