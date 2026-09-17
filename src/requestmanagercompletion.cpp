#include "requestmanager.h"

#include "requestredirect.h"

#include <QDebug>
#include <QMutexLocker>
#include <QNetworkReply>
#include <QVariant>

void RequestManager::replyReceived(QNetworkReply *reply)
{
    // sms.exe:0x1401364A0. Every submitted ID owns a reply and a waiter.
    QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    quint64 id = reply->request().attribute(
        static_cast<QNetworkRequest::Attribute>(1002), 0).toULongLong();
    if (!id)
        id = reply->property("id").toULongLong();
    const auto retainedReply = m_replies.value(id);
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (reply->error() != QNetworkReply::NoError && status < 100)
        qCWarning(m_logCategory).noquote().nospace() << "Request error; reply:";
    --m_activeRequestCount;
    storeReplyBody(reply);
    const int redirection = redirectReply(retainedReply);
    if (redirection != 0) {
        retainedReply->setProperty("redirection", redirection);
        m_completedReplyIds.append(id);
        m_waiters.value(id)->release(100);
    }
    lock.unlock();
    emit finished(retainedReply);
    doNextRequest();
}

void RequestManager::headerReceived()
{
    // sms.exe:0x140134860. The connected sender is a QNetworkReply.
    auto *reply = static_cast<QNetworkReply *>(sender());
    const QNetworkRequest request = reply->request();
    const qint64 duration = QDateTime::currentMSecsSinceEpoch()
        - request.attribute(static_cast<QNetworkRequest::Attribute>(1001)).toLongLong();
    reply->setProperty("duration", duration);
    if ((request.attribute(static_cast<QNetworkRequest::Attribute>(1011)).toInt() & 128) != 0) {
        const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
        if (m_headerDurations.size() >= 500)
            m_headerDurations.removeFirst();
        m_headerDurations.append(duration);
    }
}

void RequestManager::readyReady()
{
    // sms.exe:0x1401359B0. This is a body-size limit, NOT the timeout.
    auto *reply = static_cast<QNetworkReply *>(sender());
    qint64 limit = m_maximumStoredResponseBytes;
    if ((reply->request().attribute(
            static_cast<QNetworkRequest::Attribute>(1011)).toInt() & 2048) != 0)
        limit = 15728640;
    if (reply->bytesAvailable() >= limit) {
        storeReplyBody(reply);
        reply->abort();
    }
}

int RequestManager::redirectReply(const QSharedPointer<QNetworkReply> &reply)
{
    // sms.exe:0x140135CA0. The native first dereferences its retained reply.
    const auto prepared = prepareRequestRedirect(
        bool(reply), reply->request(), reply->url(),
        reply->attribute(QNetworkRequest::RedirectionTargetAttribute), m_secondLimit);
    if (!prepared.isPrepared())
        return static_cast<int>(prepared.result);
    // Check scope validator before following redirect
    if (m_redirectValidator && !m_redirectValidator(prepared.request.url())) {
        qCDebug(m_logCategory) << "Redirect blocked by scope:" << prepared.request.url().toString();
        return 6; // Custom code for scope rejection
    }
    ++m_redirectCount; // sms.exe:0x140135E99, native +136, even if submit fails.
    return submitPreparedRequest(prepared.request) ? 0 : 5;
}
