// gui.exe:0x140117380/0x1401334A0/0x140133130. Slot8 kindName, slot16 name;
// verified vtable 0x1402CCB60. QVariant origin metatype is qulonglong.
#include "scriptevent.h"

#include <QByteArray>
#include <QNetworkRequest>
#include <QUrl>
#include <QVariant>
#include <QString>

namespace {

QString requestMethodString(const QNetworkRequest &request)
{
    const QByteArray method = request.attribute(QNetworkRequest::Attribute(10)).toByteArray();
    return QString::fromUtf8(method);
}

bool requestManipulated(const QNetworkRequest &request)
{
    const QString value = request.attribute(QNetworkRequest::Attribute(1013)).value<QString>();
    return !value.isNull();
}

quint64 requestOrigin(const QNetworkRequest &request)
{
    const QVariant v = request.attribute(QNetworkRequest::Attribute(1012));
    return v.value<quint64>();
}

qint32 requestSession(const QNetworkRequest &request)
{
    return request.attribute(QNetworkRequest::Attribute(1010)).toInt();
}

qint32 requestFlags(const QNetworkRequest &request)
{
    return request.attribute(QNetworkRequest::Attribute(1011)).toInt();
}

}

QString describeScriptWork(const ScriptWorkItem &work)
{
    const QString responseDescription = describeScriptResponse(work.response);
    const QString parameterDescription = describeScriptParameter(work.parameter);
    const QString eventDescription =
        QStringLiteral("{type: %1, isValid:%2, args:'%3'}")
            .arg(quint64(work.event.type))
            .arg(work.event.type != 0 ? 1 : 0)
            .arg(work.event.data.toString());

    return QStringLiteral("{request:%1, parameter:%2, event:%3}")
        .arg(responseDescription, parameterDescription, eventDescription);
}

QString describeScriptResponse(const NetworkResponsePtr &response)
{
    if (nullptr == response)
        return QStringLiteral("null");

    const QNetworkRequest request = response->request;
    const QString method = requestMethodString(request);
    const QString url = response->url.toString();

    return QStringLiteral("{url:'%2', method:'%3', status:%4, timeout:%5, "
                          "partial:%6, manipulated:%7, errorCode:%8, "
                          "errorDetails:'%9', origin:%10, session:%11, flags:%12}")
        .arg(url, method)
        .arg(qint32(response->statusCode))
        .arg(response->error == 5 ? 1 : 0)
        .arg(response->error == 7 ? 1 : 0)
        .arg(requestManipulated(request) ? 1 : 0)
        .arg(qint32(response->error))
        .arg(qint32(response->socketError))
        .arg(requestOrigin(request))
        .arg(requestSession(request))
        .arg(requestFlags(request));
}

QString describeScriptParameter(const ParameterInjectionPtr &parameter)
{
    if (nullptr == parameter)
        return QStringLiteral("null");

    QString vectorString = QStringLiteral("null");
    if (nullptr != parameter->m_vector)
    {
        vectorString = QStringLiteral("{actions: %1, isValid: %2}")
            .arg(parameter->m_vector->supportedFlagsRaw())
            .arg(parameter->m_vector->isValid() ? 1 : 0);
    }

    const QString kind = parameter->kindName();
    const QString value = parameter->value(QString(), 0);
    const QString name = parameter->name();
    return QStringLiteral("{name: '%1', value: '%2', type: '%3', isValid: %4, vector:%5}")
        .arg(name, value, kind)
        .arg(parameter->isValid() ? 1 : 0)
        .arg(vectorString);
}
