#include "manipulator.h"
#include "parameterinjection.h"
#include "keyvalueinjectionvector.h"
#include "httpclient.h"
#include <QLoggingCategory>
#include <QMessageLogger>
#include <QNetworkRequest>
#include <QSharedPointer>
#include <QUrl>


// gui.exe:0x1401118E0
void Manipulator::headerParameters(const NetworkResponsePtr &reply)
{
    const HttpResponse &response = *reply; // gui.exe:0x140111929 reads reply->field170
    if (response.field170) {
        return;
    }
    // gui.exe:0x140111929
    if (!m_headerConstraint.acceptAndRecord(response.url)) {
        return;
    }

    // --- Referer --- (gui.exe:0x140111940..0x140111B4B)
    const QByteArray refererUrl = response.url.toString().toUtf8();
    {
        auto vector = QSharedPointer<KeyValueInjectionVector>::create(
            QByteArrayLiteral("Referer"), refererUrl);
        auto injection = QSharedPointer<HeaderParameterInjection>::create(
            vector, QStringLiteral("Referer"), QString::fromUtf8(refererUrl));
        manipulate(injection, 4096, reply);
    }

    // --- User-Agent --- (gui.exe:0x140111B8D..0x140111D86)
    {
        auto vector = QSharedPointer<KeyValueInjectionVector>::create(
            QByteArrayLiteral("User-Agent"), refererUrl);
        const QByteArray rawUserAgent = response.request.rawHeader(QByteArrayLiteral("User-Agent"));
        auto injection = QSharedPointer<HeaderParameterInjection>::create(
            vector, QStringLiteral("User-Agent"), QString::fromUtf8(rawUserAgent));
        manipulate(injection, 4096, reply);
    }
}
