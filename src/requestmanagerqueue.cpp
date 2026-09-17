#include "requestmanager.h"

#include <QMutexLocker>
#include <QNetworkReply>
#include <QVariant>

QNetworkRequest RequestManager::takeNextRequest()
{
    // sms.exe:0x140134C40. A paused queue permits requests without bit 64.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (m_requestQueue.isEmpty())
        return {};
    if (m_state == 0)
        return m_requestQueue.takeFirst();
    if (m_state == 2) {
        for (qsizetype i = 0; i < m_requestQueue.size(); ++i) {
            const int flags = m_requestQueue.at(i).attribute(
                static_cast<QNetworkRequest::Attribute>(1011)).toInt();
            if ((flags & 64) == 0)
                return m_requestQueue.takeAt(i);
        }
    }
    return {};
}

void RequestManager::doNextRequest()
{
    // sms.exe:0x140133BD0. Only the limit/count read is inside this lock.
    for (;;) {
        quint64 active;
        quint32 limit;
        {
            const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
            active = m_activeRequestCount;
            limit = static_cast<quint32>(m_firstLimit);
        }
        if (active >= limit || !submitPreparedRequest(takeNextRequest()))
            return;
    }
}

void RequestManager::pause()
{
    // sms.exe:0x140135070; meta-call index 3.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_state = 2;
}

void RequestManager::resume()
{
    // sms.exe:0x140136950; meta-call index 4. No pump in this method.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_state = 0;
}

void RequestManager::stop()
{
    // sms.exe:0x1401375E0; meta-call index 2. Waiters must exist for queued IDs.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_state = 1;
    while (!m_requestQueue.isEmpty()) {
        const QNetworkRequest request = m_requestQueue.takeFirst();
        const quint64 id = request.attribute(
            static_cast<QNetworkRequest::Attribute>(1002), 0).toULongLong();
        const auto waiter = m_waiters.value(id);
        waiter->release(100);
        m_waiters.remove(id);
    }
    // Keep a shared snapshot alive across abort(), which can re-enter finish.
    const auto replies = m_replies;
    for (auto it = replies.cbegin(); it != replies.cend(); ++it)
        it.value()->abort();
}
