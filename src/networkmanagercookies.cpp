#include "networkmanager.h"

#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkCookie>
#include <QNetworkCookieJar>
#include <QUrl>

// gui.exe:0x14012DF20 - lookup strictly by key; no key-0 fallback here
// (unlike selectedManager). Missing key/null manager yields empty list.
QList<QNetworkCookie> NetworkManager::cookiesForUrl(const QUrl &url, qint32 key) const
{
    QMutexLocker locker(&m_mutex);
    const auto it = m_managersByKey.constFind(key);
    if (it == m_managersByKey.constEnd()) // gui.exe:0x14012DF20 else branch
        return QList<QNetworkCookie>();
    QNetworkAccessManager *manager = it.value();
    if (manager == nullptr)
        return QList<QNetworkCookie>();
    QNetworkCookieJar *jar = manager->cookieJar(); // gui.exe:0x14012DFC1
    return jar->cookiesForUrl(url); // gui.exe:0x14012DFD3
}
