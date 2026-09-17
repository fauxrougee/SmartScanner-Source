#include "manipulator.h"
#include "jsonobjectyinjectionvector.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QLoggingCategory>
#include <QMessageLogger>
#include <QUrlQuery>

// gui.exe:0x140111E80 (jsonParameters).
void Manipulator::jsonParameters(const QByteArray &payload, const NetworkResponsePtr &reply)
{
    QJsonParseError parseError{};
    QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError)
    {
        QString text = QString::fromUtf8(payload);
        text.replace(m_jsonExpression, QStringLiteral("\\1\"\\2\":"));
        document = QJsonDocument::fromJson(text.toUtf8(), &parseError);
    }

    const QJsonObject object = document.object();
    const QStringList keys = object.keys();
    for (const QString &key : keys)
    {
        const QJsonValue value = object.value(key);
        QString valueString;
        if (value.isString())
            valueString = value.toString();
        else if (value.isDouble())
            valueString = QString::number(value.toDouble(), 'g', 6);
        else
            continue;

        const QList<QPair<QString, QString>> packetItems =
            QUrlQuery(QString::fromUtf8(payload)).queryItems();
        if (!m_queryState.acceptParameter(reply->url, {key, valueString},
                                           packetItems, true))
            continue;

        ParameterInjectionPtr injection(new PostParameterInjection(
            QSharedPointer<InjectionVector>(new JsonObjectyInjectionVector(object, key)),
            key, valueString));
        manipulate(injection, 512, reply);
    }
}
