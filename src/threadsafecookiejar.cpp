#include "threadsafecookiejar.h"

#include <QMutexLocker>

ThreadSafeCookieJar::ThreadSafeCookieJar(QObject *parent) : QNetworkCookieJar(parent) {}

QList<QNetworkCookie> ThreadSafeCookieJar::cookiesForUrl(const QUrl &url) const {
    QMutexLocker<QRecursiveMutex> locker(&m_mutex);
    QList<QNetworkCookie> result = QNetworkCookieJar::cookiesForUrl(url);

    // sms.exe:0x14015FC50 follows the Qt result with every stored cookie whose
    // domain QString is null. QString::isEmpty() would be incorrect here.
    for (const QNetworkCookie &cookie : QNetworkCookieJar::allCookies()) {
        if (cookie.domain().isNull())
            result.append(cookie);
    }
    return result;
}

bool ThreadSafeCookieJar::deleteCookie(const QNetworkCookie &cookie) {
    QMutexLocker<QRecursiveMutex> locker(&m_mutex);
    return QNetworkCookieJar::deleteCookie(cookie);
}

bool ThreadSafeCookieJar::insertCookie(const QNetworkCookie &cookie) {
    QMutexLocker<QRecursiveMutex> locker(&m_mutex);
    return QNetworkCookieJar::insertCookie(cookie);
}

bool ThreadSafeCookieJar::setCookiesFromUrl(const QList<QNetworkCookie> &cookies, const QUrl &url) {
    QMutexLocker<QRecursiveMutex> locker(&m_mutex);
    return QNetworkCookieJar::setCookiesFromUrl(cookies, url);
}

bool ThreadSafeCookieJar::updateCookie(const QNetworkCookie &cookie) {
    QMutexLocker<QRecursiveMutex> locker(&m_mutex);
    return QNetworkCookieJar::updateCookie(cookie);
}
