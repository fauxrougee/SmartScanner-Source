#include "networkmanager.h"

#include <QAuthenticator>
#include <QIODevice>
#include <QNetworkAccessManager>
#include <QNetworkCookie>
#include <QNetworkCookieJar>
#include <QNetworkDiskCache>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QStandardPaths>
#include <QMutexLocker>
#include <utility>

namespace {

constexpr auto nativeAttribute = [](int value) {
    return static_cast<QNetworkRequest::Attribute>(value);
};

HttpResponse::Error mapNetworkError(QNetworkReply::NetworkError error)
{
    // gui.exe:0x140133D17.  Keep the observed numeric cases rather than
    // attaching Qt enum labels that can differ between Qt releases.
    switch (static_cast<int>(error)) {
    case 1:
    case 2:
    case 3:
    case 6:
    case 7:
    case 8:
    case 9:
    case 101:
    case 102:
    case 103:
    case 105:
        return HttpResponse::ConnectionError;
    case 4:
    case 104:
        return HttpResponse::Timeout;
    case 5:
        return static_cast<HttpResponse::Error>(6);
    case 10:
    case 11:
        return static_cast<HttpResponse::Error>(4);
    case 99:
    case 199:
    case 301:
        return static_cast<HttpResponse::Error>(8);
    case 302:
    case 399:
        return static_cast<HttpResponse::Error>(2);
    default:
        return HttpResponse::NoError;
    }
}

} // namespace

NetworkManager::NetworkManager(const QString &scanId, QObject *parent) : QObject(parent) {
    // Directly observed in NetworkManager_ctor: access manager, optional disk
    // cache, and `authenticationRequired` -> `authenticate` connection.
    m_constructedAt = QDateTime::currentDateTime(); // gui.exe:0x14012B32F
    m_accessManager = new QNetworkAccessManager(this);
    m_managersByKey.insert(0, m_accessManager);
    if (!scanId.isNull()) {
        m_diskCache = new QNetworkDiskCache(this);
        m_cacheDirectory = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
                          + QStringLiteral("/scans/%1/network/").arg(scanId);
        m_diskCache->setCacheDirectory(m_cacheDirectory + QStringLiteral("0/"));
        m_accessManager->setCache(m_diskCache);
    }
    connect(m_accessManager, &QNetworkAccessManager::authenticationRequired,
            this, &NetworkManager::authenticate);
}

bool NetworkManager::isIdle() const
{
    // gui.exe:0x140130970: active or queued work makes the manager non-idle.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    return m_activeRequests == 0 && m_queuedRequests == 0;
}

quint32 NetworkManager::activeRequests() const
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    return m_activeRequests;
}

quint32 NetworkManager::queuedRequests() const
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    return m_queuedRequests;
}

quint32 NetworkManager::totalRequests() const
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    return m_totalRequests;
}

quint32 NetworkManager::completedRequests() const
{
    // Scanner's map producer, gui.exe:0x1400E9470.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    return m_totalRequests - m_queuedRequests - m_activeRequests;
}

QUrl NetworkManager::lastUrl() const
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    return m_lastUrl;
}

void NetworkManager::setConcurrentLimit(qint32 limit)
{
    // gui.exe:0x140132B00: lock, clamp values below 2 to one, and invoke the
    // queue pump before releasing its recursive mutex.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_concurrentLimit = limit > 1 ? limit : 1;
    pump();
}

QDataStream &operator<<(QDataStream &stream, const NetworkManager &manager)
{
    // gui.exe:0x1400E2997-0x1400E29ED. No concurrent-limit or queue payload.
    stream << manager.m_state << manager.m_activeRequests << manager.m_totalRequests
           << manager.m_lastUrl << manager.m_constructedAt
           << manager.m_maximumResponseBodyBytes << manager.m_field70;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, NetworkManager &manager)
{
    // gui.exe:0x1400E1D61-0x1400E1DBA writes fields as it reads them; there is
    // no additional all-or-nothing commit or locking in this native slice.
    stream >> manager.m_state >> manager.m_activeRequests >> manager.m_totalRequests
           >> manager.m_lastUrl >> manager.m_constructedAt
           >> manager.m_maximumResponseBodyBytes >> manager.m_field70;
    return stream;
}

void NetworkManager::setAuthenticationCredentials(const QString &user,
                                                  const QString &password)
{
    // gui.exe:0x140132AC0 writes the two adjacent manager QString fields.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_authenticationUser = user;
    m_authenticationPassword = password;
}

void NetworkManager::setTransferTimeout(qint64 timeout)
{
    // gui.exe:0x140132B70 stores zero for every non-positive value.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_transferTimeout = timeout > 0 ? timeout : 0;
}

void NetworkManager::setUserAgent(const QString &userAgent)
{
    // gui.exe:0x1400E3120 assigns ScanConfig+0x60 to NetworkManager+0xd0.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_userAgent = userAgent;
}

void NetworkManager::setDefaultHeaders(const QList<QPair<QByteArray, QByteArray>> &headers)
{
    // gui.exe:0x14001BB80 assigns the header-pair list at NetworkManager+0xe8.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_defaultHeaders = headers;
}

void NetworkManager::setProxy(const QNetworkProxy &proxy)
{
    // gui.exe:0x1400E3363-0x1400E3379 applies the recovered proxy to every
    // manager in its pool; 0x1400E3534-0x1400E3548 also sets the Qt global.
    for (QNetworkAccessManager *manager : std::as_const(m_managersByKey))
        manager->setProxy(proxy);
    QNetworkProxy::setApplicationProxy(proxy);
}

void NetworkManager::setCookies(const QList<QNetworkCookie> &cookies)
{
    // gui.exe:0x1400E338A-0x1400E3424 loops over ScanConfig+0x150 and calls
    // QNetworkCookieJar::insertCookie for each entry on the default manager.
    QNetworkCookieJar *const jar = m_accessManager->cookieJar();
    for (const QNetworkCookie &cookie : cookies)
        jar->insertCookie(cookie);
}

QFuture<NetworkManager::ResponsePointer> NetworkManager::submit(
    const QNetworkRequest &request, const QByteArray &method,
    const QByteArray &payload, qint32 field1011, const QVariant &field1012,
    qint32 accessManagerKey, qint32 queueSelector)
{
    // gui.exe:0x140132220 creates and returns a QFuture immediately.  A
    // stopped manager cancels that future without inserting a work item.
    auto promise = QSharedPointer<QPromise<ResponsePointer>>::create();
    promise->start();
    const QFuture<ResponsePointer> future = promise->future();

    {
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        if (m_state == 1) {
            // gui.exe:0x1401322D3 reports a null result before cancellation.
            promise->addResult(ResponsePointer{});
            promise->future().cancel();
            promise->finish();
            return future;
        }

        // gui.exe:0x14013263B-0x14013265B. One list: selector 1 inserts at
        // index zero; every other selector inserts at size (the tail).
        PendingRequest work{request, method, payload, field1011, field1012,
                            accessManagerKey, queueSelector, promise};
        if (queueSelector == 1)
            m_pendingRequests.prepend(std::move(work));
        else
            m_pendingRequests.enqueue(std::move(work));
        ++m_queuedRequests;
        ++m_totalRequests;
    }
    pump();
    return future;
}

void NetworkManager::stop()
{
    // gui.exe:0x14012D300. Under the manager mutex, this route becomes
    // terminal and detaches the pending container before aborting active
    // replies. Pending futures receive the native null response only when
    // they have not already been cancelled/finished and have no result.
    QQueue<PendingRequest> pending;
    QSet<QNetworkReply *> activeReplies;
    {
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        if (m_state == 1)
            return;
        m_state = 1;
        pending.swap(m_pendingRequests);
        m_queuedRequests = 0;
        activeReplies = m_activeReplies;
    }

    for (QNetworkReply *reply : activeReplies) {
        if (reply)
            reply->abort();
    }

    while (!pending.isEmpty()) {
        PendingRequest work = pending.dequeue();
        const QFuture<ResponsePointer> future = work.promise->future();
        if (!future.isCanceled() && !future.isFinished() && future.resultCount() == 0)
            work.promise->addResult(ResponsePointer{});
        work.promise->future().cancel();
        work.promise->finish();
    }
}

void NetworkManager::pump()
{
    // gui.exe:0x14012ECE0 holds the recursive mutex across the whole pump.
    // 0x14012E3B0 consumes the first list entry. Canceled work does not
    // increment active. Normal work is dispatched by a queued invocation.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    while (m_state == 0
           && m_activeRequests < static_cast<quint32>(m_concurrentLimit)
           && !m_pendingRequests.isEmpty()) {
        PendingRequest work = m_pendingRequests.dequeue();
        --m_queuedRequests;
        if (work.promise->isCanceled()) {
            work.promise->finish();
            continue;
        }
        ++m_activeRequests;
        QMetaObject::invokeMethod(this,
            [this, work = std::move(work)]() mutable { dispatch(std::move(work)); },
            Qt::QueuedConnection); // native 0x14012EECB -> 0x140130AE0
    }
    if (m_activeRequests == 0 && m_pendingRequests.isEmpty())
        emit allFinished(); // native 0x14012EF47-54, before unlock.
}

void NetworkManager::dispatch(PendingRequest work)
{
    // gui.exe:0x14012EFF5-0x14012F118. The queued callback may run after
    // stop: reject it without sending, release its reserved active count.
    qint32 state;
    {
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        state = m_state;
    }
    if (state != 0) {
        work.promise->addResult(ResponsePointer{});
        work.promise->future().cancel();
        work.promise->finish();
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        --m_activeRequests;
        pump();
        return;
    }
    // gui.exe:0x140130F90 falls back to key zero, not a null manager.
    QNetworkAccessManager *const manager = selectedManager(work.accessManagerKey);
    QNetworkRequest request = work.request;
    qint64 maximumResponseBodyBytes = 0;
    qint64 transferTimeout = 0;
    QString userAgent;
    QList<QPair<QByteArray, QByteArray>> defaultHeaders;
    {
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        maximumResponseBodyBytes = m_maximumResponseBodyBytes;
        transferTimeout = m_transferTimeout;
        userAgent = m_userAgent;
        defaultHeaders = m_defaultHeaders;
    }
    // gui.exe:0x14012F1C6-0x14012F1D0: retain an explicit request timeout;
    // otherwise use the positive manager timeout.
    if (transferTimeout > 0 && request.transferTimeout() <= 0)
        request.setTransferTimeout(static_cast<int>(transferTimeout));
    // gui.exe:0x14012F1D6-0x14012F23F: only missing raw headers inherit the
    // manager-level values, preserving caller-specific headers.
    for (const auto &header : defaultHeaders) {
        if (!request.hasRawHeader(header.first))
            request.setRawHeader(header.first, header.second);
    }
    // gui.exe:0x14012F241 tests QString length; empty means no override.
    if (!userAgent.isEmpty()
        && !request.header(QNetworkRequest::UserAgentHeader).isValid()) {
        request.setHeader(QNetworkRequest::UserAgentHeader, userAgent);
    }
    request.setAttribute(nativeAttribute(1011), work.field1011);
    request.setAttribute(nativeAttribute(1012), work.field1012);
    request.setAttribute(nativeAttribute(1003), work.payload);
    request.setAttribute(QNetworkRequest::CustomVerbAttribute, work.method);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         (work.field1011 & 0x200) ? 2 : 0);
    request.setAttribute(nativeAttribute(8), 1); // gui.exe:0x14012F2FD
    request.setAttribute(nativeAttribute(22), 0); // gui.exe:0x14012F332
    // Disable automatic redirects - we handle them manually with scope validation
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         static_cast<int>(QNetworkRequest::ManualRedirectPolicy));

    {
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        m_lastUrl = request.url();
        m_constructedAt = QDateTime::currentDateTime(); // gui.exe:0x14012F383
    }

    QList<QNetworkCookie> savedCookies, injectedCookies;
    prepareCookies(request, manager, savedCookies, injectedCookies);
    QNetworkReply *reply = nullptr;
    if (work.method == QByteArrayLiteral("GET"))
        reply = manager->get(request);
    else if (work.method == QByteArrayLiteral("POST"))
        reply = manager->post(request, work.payload);
    else if (work.method == QByteArrayLiteral("PUT"))
        reply = manager->put(request, work.payload);
    else if (work.method == QByteArrayLiteral("DELETE"))
        reply = manager->deleteResource(request);
    else
        reply = manager->sendCustomRequest(request, work.method, work.payload);

    // gui.exe:0x14012F574-0x14012F67B: remove injected cookies then restore
    // the saved URL cookies immediately after dispatch, not after completion.
    for (const QNetworkCookie &cookie : std::as_const(injectedCookies))
        manager->cookieJar()->deleteCookie(cookie);
    for (const QNetworkCookie &cookie : std::as_const(savedCookies))
        manager->cookieJar()->insertCookie(cookie);

    if (!reply) {
        finish(std::move(work), nullptr);
        return;
    }

    reply->setParent(this);
    {
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        m_activeReplies.insert(reply);
    }
    auto timer = QSharedPointer<QElapsedTimer>::create();
    timer->start();
    connect(reply, &QNetworkReply::metaDataChanged, reply, [reply, timer] {
        // gui.exe:0x140130C50 stores the elapsed time as nm_ttfb_ms.
        reply->setProperty("nm_ttfb_ms", timer->elapsed());
    });
    connect(reply, &QNetworkReply::sslErrors, reply,
            [reply](const QList<QSslError> &) {
                // gui.exe:0x140130CF0 invokes QNetworkReply's virtual
                // ignore-SSL-errors entry on this reply.
                reply->ignoreSslErrors();
            });
    // gui.exe:0x14012F81C-0x14012F8C3.  Attribute 1011 is a bit mask;
    // bit 2048 opts this request out of the manager-level body cap.  The
    // native reserves one extra byte, preserves the buffered prefix when the
    // cap is crossed, records truncation, then aborts the reply.
    if (maximumResponseBodyBytes > 0 && (work.field1011 & 2048) == 0) {
        reply->setReadBufferSize(maximumResponseBodyBytes + 1);
        connect(reply, &QIODevice::readyRead, this,
                [reply, maximumResponseBodyBytes] {
                    if (reply->bytesAvailable() > maximumResponseBodyBytes) {
                        reply->setProperty("nm_truncated", true);
                        reply->setProperty("nm_partialBody", reply->readAll());
                        reply->abort();
                    }
                });
    }
    connect(reply, &QNetworkReply::finished, this,
            [this, work = std::move(work), reply] () mutable {
                finish(std::move(work), reply);
            });
}

QNetworkAccessManager *NetworkManager::selectedManager(qint32 key) const
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    const auto found = m_managersByKey.constFind(key);
    return found != m_managersByKey.cend() ? found.value() : m_managersByKey.value(0);
}

void NetworkManager::prepareCookies(QNetworkRequest &request,
    QNetworkAccessManager *manager, QList<QNetworkCookie> &saved,
    QList<QNetworkCookie> &injected)
{
    // gui.exe:0x140132BE0; QVariant-to-QList conversion, not parsing raw bytes.
    injected = request.header(QNetworkRequest::CookieHeader).value<QList<QNetworkCookie>>();
    if (!injected.isEmpty()) {
        saved = manager->cookieJar()->cookiesForUrl(request.url());
        for (const QNetworkCookie &cookie : std::as_const(saved))
            manager->cookieJar()->deleteCookie(cookie);
        for (const QNetworkCookie &cookie : std::as_const(injected))
            manager->cookieJar()->insertCookie(cookie);
    }
    QByteArray raw;
    const QList<QNetworkCookie> cookies = manager->cookieJar()->cookiesForUrl(request.url());
    for (const QNetworkCookie &cookie : cookies) {
        raw += cookie.toRawForm(QNetworkCookie::NameAndValueOnly);
        raw += "; ";
    }
    request.setAttribute(nativeAttribute(1006), raw);
}

void NetworkManager::finish(PendingRequest work, QNetworkReply *reply)
{
    // gui.exe:0x14012CD20: publish one response unless the future was
    // cancelled, mark it finished, delete the reply, remove the active work,
    // and immediately pump another queued request.
    if (!reply) {
        // gui.exe:0x14012EF90 cancellation branch: no reply means no result
        // signal or result object; the associated future is cancelled.
        work.promise->future().cancel();
    } else {
        // Handle manual redirects with scope validation
        const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QUrl redirectUrl = reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
        if (!redirectUrl.isEmpty() && statusCode >= 300 && statusCode < 400) {
            QUrl resolvedUrl = redirectUrl.isRelative()
                ? reply->url().resolved(redirectUrl) : redirectUrl;
            // Check scope validator before following redirect
            bool allowRedirect = true;
            {
                const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
                if (m_scopeValidator)
                    allowRedirect = m_scopeValidator(resolvedUrl);
            }
            if (allowRedirect) {
                // Follow the redirect by creating a new request
                QNetworkRequest newRequest = reply->request();
                newRequest.setUrl(resolvedUrl);
                work.request = newRequest;
                // Requeue the request
                reply->deleteLater();
                {
                    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
                    m_activeReplies.remove(reply);
                    --m_activeRequests;
                    m_pendingRequests.prepend(std::move(work));
                    ++m_queuedRequests;
                }
                pump();
                return;
            }
            // Redirect blocked by scope - fall through to emit response as-is
        }

        // The dispatched request (with attributes 1003/1006/1011/1012) is the
        // one carried by the reply; work.request predates those attributes.
        const ResponsePointer response = responseFromReply(reply, reply->request());
        // gui.exe:0x14012CD20 calls signal index 0 before publishing the
        // future result and running its continuation.
        emit finished(response);
        if (!work.promise->isCanceled())
            work.promise->addResult(response);
    }
    work.promise->finish();

    if (reply)
        reply->deleteLater();
    {
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        m_activeReplies.remove(reply);
        --m_activeRequests;
    }
    pump();
}

NetworkManager::ResponsePointer NetworkManager::responseFromReply(
    QNetworkReply *reply, const QNetworkRequest &request)
{
    auto response = QSharedPointer<HttpResponse>::create();
    if (!reply)
        return response;

    // gui.exe:0x140133CC0.
    response->error = mapNetworkError(reply->error());
    if (reply->property("nm_truncated").toBool())
        response->error = static_cast<HttpResponse::Error>(7);
    if (reply->property("nm_timeout").toBool()) {
        response->error = HttpResponse::Timeout;
        response->socketError = 0;
    } else {
        response->socketError = static_cast<qint32>(reply->error());
    }
    response->url = reply->url();
    response->request = request;
    response->statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    response->durationMilliseconds = reply->property("nm_ttfb_ms").toLongLong();
    if (response->durationMilliseconds == 0)
        response->durationMilliseconds = reply->property("nm_ttf_ms").toLongLong();

    response->raw = QByteArrayLiteral("HTTP/1.1 ");
    response->raw.append(QByteArray::number(response->statusCode));
    response->statusTextOffset = response->raw.size();
    response->raw.append(
        reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toByteArray());
    response->statusTextLength = response->raw.size() - response->statusTextOffset;
    response->raw.append("\r\n");

    for (const auto &header : reply->rawHeaderPairs()) {
        HttpResponse::HeaderRange ranges;
        ranges.name = {response->raw.size(), header.first.size()};
        response->raw.append(header.first);
        response->raw.append(':');
        ranges.value = {response->raw.size(), header.second.size()};
        response->raw.append(header.second);
        response->raw.append("\r\n");
        response->field120.append(ranges);
    }
    response->raw.append("\r\n");
    response->bodyOffset = response->raw.size();
    response->raw.append(reply->property("nm_partialBody").toByteArray());
    reply->setProperty("nm_partialBody", QVariant());
    if (reply->isOpen())
        response->raw.append(reply->readAll());
    response->bodyLength = response->raw.size() - response->bodyOffset;
    return response;
}

void NetworkManager::authenticate(QNetworkReply *reply, QAuthenticator *authenticator) {
    // sms.exe:0x140126820.
    if (!reply || !authenticator)
        return;

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
    if (authenticator->user() == m_authenticationUser
        && authenticator->password() == m_authenticationPassword)
        return;

    authenticator->setUser(m_authenticationUser);
    authenticator->setPassword(m_authenticationPassword);
}

void NetworkManager::setScopeValidator(std::function<bool(const QUrl &)> validator)
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_scopeValidator = std::move(validator);
}
