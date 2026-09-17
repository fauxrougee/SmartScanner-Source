#include "manipulator.h"
#include "cookieinjectionvector.h"
#include "parameterexclusion.h"
#include "parameterinjection.h"
#include "httpclient.h"

#include <QByteArray>
#include <QByteArrayView>
#include <QNetworkCookie>
#include <QString>
#include <QStringList>
#include <QUrl>

// gui.exe:0x1401110F0 - fetch cookies via the manager (never parse the raw
// Set-Cookie value), build one CookieParameterInjection per cookie, dedup by
// (scheme + host(FullyDecoded|133169152) + path + "?" + name) case-sensitively,
// and dispatch to manipulate(..., 2048, reply).
void Manipulator::cookieParameters(const NetworkResponsePtr &reply)
{
    static const QByteArrayView kSetCookie("set-cookie", 10);

    // Locate a response header whose name case-insensitively equals set-cookie.
    const QList<HttpResponse::HeaderRange> &headers = reply->field120;
    const char *rawData = reply->raw.constData();
    bool hasSetCookie = false;
    for (const HttpResponse::HeaderRange &range : headers) {
        const QByteArrayView name(rawData + range.name.offset, range.name.length);
        if (name.compare(kSetCookie, Qt::CaseInsensitive) == 0) {
            hasSetCookie = true;
            break;
        }
    }
    if (!hasSetCookie)
        return;

    if (networkManager == nullptr)
        return;

    // gui.exe:0x1401111E1 - always key 0.
    const QList<QNetworkCookie> cookies = networkManager->cookiesForUrl(reply->url, 0);

    qint32 index = 0;
    for (const QNetworkCookie &cookie : cookies) {
        const qint32 selectedIndex = index;
        ++index;

        const QString cookieName = QString::fromUtf8(cookie.name()); // gui.exe:0x14011140A
        const QByteArray decoded =
            QByteArray::fromPercentEncoding(cookie.value()); // gui.exe:0x140111387
        const QString cookieValue = QString::fromUtf8(decoded); // gui.exe:0x1401113C8

        auto vector = QSharedPointer<CookieInjectionVector>::create(cookies, selectedIndex);
        auto parameter = QSharedPointer<CookieParameterInjection>::create(
            vector, cookieName, cookieValue); // gui.exe:0x140111476 (kind=4)

        if (exclusions) {
            if (parameterExcluded(*exclusions, *parameter, reply->url.toString()))
                continue; // gui.exe:0x140111573
        }

        // Signature: scheme + host(FullyDecoded|133169152) + path + "?" + name.
        QString signature = reply->url.scheme(); // gui.exe:0x140111618
        signature += reply->url.host(QUrl::FullyDecoded); // gui.exe:0x140111606
        signature += cookie.path(); // gui.exe:0x1401115E1
        signature += QStringLiteral("?"); // gui.exe:0x14011167C (unk_1402CCAE0 = '?')
        signature += parameter->name(); // gui.exe:0x1401115CE

        // Case-sensitive dedup; append BEFORE dispatch.
        if (m_cookieSignatures.contains(signature))
            continue; // gui.exe:0x140111754 (Qt::CaseSensitive)
        m_cookieSignatures.append(signature); // gui.exe:0x14011176E

        manipulate(parameter, 2048, reply); // gui.exe:0x1401117C2
    }
}
