#include "requestmanager.h"

#include <QDebug>
#include <QMutexLocker>
#include <QNetworkReply>
#include <QVariant>

void RequestManager::garbageCollect()
{
    // sms.exe:0x140134000. A collected ID is erased from all three containers.
    for (int index = 0; index < m_completedReplyIds.size(); ) {
        quint64 id;
        QSharedPointer<QNetworkReply> reply;
        {
            const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
            id = m_completedReplyIds.at(index);
            reply = m_replies.value(id);
        }
        if (reply) {
            const auto request = reply->request();
            const qint64 started = request.attribute(
                static_cast<QNetworkRequest::Attribute>(1001)).toLongLong();
            const qint64 duration = reply->property("duration").toLongLong();
            if (m_completedReplyIds.size() > 50
                || QDateTime::currentMSecsSinceEpoch() - (started + duration) >= 3000
                || (request.attribute(static_cast<QNetworkRequest::Attribute>(1011)).toInt() & 256) != 0) {
                const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
                m_replies.remove(id);
                // 0x140131610 scans/compacts every match, not only this index.
                m_completedReplyIds.removeAll(id);
                m_waiters.remove(id);
                continue;
            }
        }
        ++index;
    }

    // Native 0x14013439E shares the table before walking/aborting it.
    const auto replies = m_replies;
    for (auto it = replies.cbegin(); it != replies.cend(); ++it) {
        const auto &reply = it.value();
        if (!reply)
            continue;
        const qint64 started = reply->request().attribute(
            static_cast<QNetworkRequest::Attribute>(1001)).toLongLong();
        if (QDateTime::currentMSecsSinceEpoch() - started > m_timeoutMilliseconds) {
            qCWarning(m_logCategory).noquote().nospace() << "Request time out; reply:";
            reply->setProperty("timedout", 1); // QVariant(int), not bool.
            reply->setProperty("duration", m_timeoutMilliseconds);
            storeReplyBody(reply.data());
            reply->abort();
        }
    }
}
