#include "requestmanager.h"

#include "threadsafecookiejar.h"

#include <QAuthenticator>
#include <QDir>
#include <QNetworkDiskCache>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSslError>
#include <QStandardPaths>

#include <random>

namespace {

quint64 requestManagerCacheSuffix()
{
    // sms.exe:0x140134640. The native code seeds a process-wide random engine
    // from std::random_device and draws in this inclusive range. Each draw is
    // checked against the RequestManager's internal map at +64, retrying while
    // that map already contains the candidate.
    static std::mt19937_64 engine(std::random_device{}());
    static std::uniform_int_distribution<quint64> distribution(1, 0x5AF3107A3FFFULL);
    return distribution(engine);
}

bool replyRequestAttributeMaskIsSet(const QNetworkReply *reply, int mask)
{
    // sms.exe:0x140137AE0. Attribute 1011 is application-defined in the
    // native request model, hence the retained raw numeric value.
    if (!reply)
        return false;
    const int attributes = reply->request()
                               .attribute(static_cast<QNetworkRequest::Attribute>(1011))
                               .toInt();
    return mask == 0 ? attributes == 0 : (attributes & mask) == mask;
}

} // namespace

RequestManager::RequestManager(QObject *parent) : QObject(parent) {
    // These construction calls, signal/slot spellings and defaults are direct
    // observations from RequestManager_ctor.
    m_constructedAt = QDateTime::currentDateTime(); // sms.exe:0x140131EA4
    // sms.exe:0x140131EEE / 0x140131FC3 / 0x140131FE0 and hash reserves.
    m_requestQueue.reserve(100);
    m_waiters.reserve(100);
    m_headerDurations.reserve(500);
    m_completedReplyIds.reserve(50);
    m_replies.reserve(100);
    m_accessManager.setCookieJar(new ThreadSafeCookieJar(this));

    auto *diskCache = new QNetworkDiskCache;
    const auto cachePath = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
                           + QLatin1Char('/') + QString::number(requestManagerCacheSuffix());
    // sms.exe retains this QDir at +0x130, rather than using a temporary QDir.
    m_cacheDirectory.setPath(cachePath);
    if (m_cacheDirectory.mkpath(m_cacheDirectory.absolutePath())) {
        diskCache->setCacheDirectory(cachePath);
        m_accessManager.setCache(diskCache); // ownership transfers to manager
    } else {
        m_cacheDirectory.setPath(QString());
        delete diskCache;
    }

    connect(&m_accessManager, &QNetworkAccessManager::finished,
            this, &RequestManager::replyReceived);
    connect(&m_accessManager, &QNetworkAccessManager::authenticationRequired,
            this, &RequestManager::authenticate);
    connect(&m_accessManager, &QNetworkAccessManager::sslErrors,
            this, &RequestManager::handleSslErrors);
    m_garbageCollectionTimer.setInterval(3000);
    connect(&m_garbageCollectionTimer, &QTimer::timeout,
            this, &RequestManager::garbageCollect, Qt::QueuedConnection);
    m_garbageCollectionTimer.start();
}

void RequestManager::storeReplyBody(QNetworkReply *reply) {
    // sms.exe:0x140135880. This helper retains a bounded body as dynamic Qt
    // properties, then drains the reply regardless of whether it was partial.
    if (!reply)
        return;

    const qint64 available = reply->bytesAvailable();
    if (available <= 0)
        return;

    qint64 maximum = m_maximumStoredResponseBytes;
    if (replyRequestAttributeMaskIsSet(reply, 2048))
        maximum = 15728640;

    reply->setProperty("body", reply->read(maximum));
    reply->readAll();
    if (available > maximum)
        reply->setProperty("partial", true);
    m_totalReceivedBytes += available;
}

void RequestManager::authenticate(QNetworkReply *reply, QAuthenticator *authenticator) {
    // sms.exe:0x140133490.
    const QString requestCredentials = reply->request()
                                           .attribute(static_cast<QNetworkRequest::Attribute>(1009))
                                           .toString();
    if (!requestCredentials.isNull()) {
        const QString user = requestCredentials.section(QStringLiteral("||"), 0, 0);
        const QString password = requestCredentials.section(QStringLiteral("||"), 1, 1);
        if (authenticator->user() != user || authenticator->password() != password) {
            authenticator->setUser(user);
            authenticator->setPassword(password);
        }
        return;
    }

    if (m_authenticationUser.isNull())
        return;

    // The native code logs an invalid-credential warning and intentionally
    // leaves the authenticator unchanged when it has already retried this pair.
    if (authenticator->user() == m_authenticationUser
        && authenticator->password() == m_authenticationPassword)
        return;

    authenticator->setUser(m_authenticationUser);
    authenticator->setPassword(m_authenticationPassword);
}

void RequestManager::handleSslErrors(QNetworkReply *reply, const QList<QSslError> &errors) {
    Q_UNUSED(reply)
    Q_UNUSED(errors)
    // Deliberately do not ignore TLS errors: the binary's policy has not yet
    // been recovered and accepting invalid certificates would be speculative.
}

void RequestManager::prepareRequest(QNetworkRequest &request) const
{
    // sms.exe:0x140136E50. Only missing headers are supplied; for duplicate
    // configured names the first successful insertion wins.
    for (const auto &header : m_defaultHeaders) {
        if (!request.hasRawHeader(header.first))
            request.setRawHeader(header.first, header.second);
    }
    if (!m_userAgent.isEmpty() && !request.header(QNetworkRequest::UserAgentHeader).isValid())
        request.setHeader(QNetworkRequest::UserAgentHeader, m_userAgent);
    // Native QVariant(int), not bool. Key 22 is NOT Http2AllowedAttribute.
    request.setAttribute(static_cast<QNetworkRequest::Attribute>(8), 1);
    request.setAttribute(static_cast<QNetworkRequest::Attribute>(22), 0);
    request.setAttribute(static_cast<QNetworkRequest::Attribute>(1001),
                         QDateTime::currentMSecsSinceEpoch());
}

void RequestManager::prepareCookies(QNetworkRequest &request,
                                   QList<QNetworkCookie> &savedCookies,
                                   QList<QNetworkCookie> &injectedCookies)
{
    // sms.exe:0x140136AB0, with QVariant->QList conversion at 0x140123D50.
    // The caller supplies empty output lists. No raw Cookie reparse occurs.
    injectedCookies = request.header(QNetworkRequest::CookieHeader).value<QList<QNetworkCookie>>();
    QNetworkCookieJar *jar = m_accessManager.cookieJar();
    if (!injectedCookies.isEmpty()) {
        savedCookies = jar->cookiesForUrl(request.url());
        for (const QNetworkCookie &cookie : savedCookies)
            jar->deleteCookie(cookie);
        for (const QNetworkCookie &cookie : injectedCookies)
            jar->insertCookie(cookie);
    }
    QByteArray captured;
    const auto effective = jar->cookiesForUrl(request.url());
    for (const QNetworkCookie &cookie : effective) {
        captured.append(cookie.toRawForm(QNetworkCookie::NameAndValueOnly));
        captured.append("; ");
    }
    request.setAttribute(static_cast<QNetworkRequest::Attribute>(1006), captured);
}

void RequestManager::restoreCookies(const QList<QNetworkCookie> &savedCookies,
                                   const QList<QNetworkCookie> &injectedCookies)
{
    // sms.exe:0x140137297-0x1401373CF, after the request has been submitted.
    QNetworkCookieJar *jar = m_accessManager.cookieJar();
    for (const QNetworkCookie &cookie : injectedCookies)
        jar->deleteCookie(cookie);
    for (const QNetworkCookie &cookie : savedCookies)
        jar->insertCookie(cookie);
}

// replyReceived, headerReceived, readyReady, redirectReply defined in requestmanagercompletion.cpp
// doNextRequest, takeNextRequest, stop, pause, resume defined in requestmanagerqueue.cpp
// garbageCollect defined in requestmanagergc.cpp
// submitPreparedRequest defined in requestmanagersubmission.cpp

void RequestManager::setRedirectValidator(std::function<bool(const QUrl &)> validator) {
    m_redirectValidator = std::move(validator);
}
