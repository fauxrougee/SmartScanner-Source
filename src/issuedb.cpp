#include "issuedb.h"

#include <QDateTime>
#include <QMutexLocker>
#include <QUrl>

IssueDb::IssueDb(QObject *parent)
    : QObject(parent)
{
}

QDataStream &operator<<(QDataStream &stream, const IssueDb &db)
{
    // gui.exe:0x1400E2590; QList<Issue>, QMultiMap<qint64,Issue>, interval,
    // QSet<QUrl>. No provisioning or signal emission in this stream path.
    stream << db.m_issues << db.m_pending << db.m_pendingIntervalMs << db.m_field2C8;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, IssueDb &db)
{
    // gui.exe:0x1400E1930 and its collection readers restore the containers
    // directly, without invoking add() or changing their persisted order.
    stream >> db.m_issues >> db.m_pending >> db.m_pendingIntervalMs >> db.m_field2C8;
    return stream;
}

bool IssueDb::containsIdentity(quint64 identity)
{
    return findByIdentity(identity) != nullptr;
}

Issue *IssueDb::findByIdentity(quint64 identity)
{
    for (Issue &issue : m_issues) {
        if (issue.identity() == identity)
            return &issue;
    }
    for (auto it = m_pending.begin(); it != m_pending.end(); ++it) {
        if (it.value().identity() == identity)
            return &it.value();
    }
    return nullptr;
}

void IssueDb::insertImmediate(const Issue &issue)
{
    m_issues.append(issue);
    emit newIssueAdded(issue);
}

void IssueDb::provision(qint64 timestamp)
{
    const auto values = m_pending.values(timestamp);
    for (const Issue &issue : values)
        insertImmediate(issue);
    m_pending.remove(timestamp);
}

void IssueDb::provisionExpired()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const auto timestamps = m_pending.uniqueKeys();
    for (qint64 timestamp : timestamps) {
        if (now - timestamp > m_pendingIntervalMs)
            provision(timestamp);
    }
}

bool IssueDb::add(Issue issue, bool addPending)
{
    QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    provisionExpired();
    if (containsIdentity(issue.identity()))
        return false;

    if (addPending)
        m_pending.insert(QDateTime::currentMSecsSinceEpoch(), std::move(issue));
    else
        insertImmediate(issue);
    return true;
}

bool IssueDb::add(Issue issue)
{
    return add(std::move(issue), false);
}

bool IssueDb::addOrUpdate(Issue issue)
{
    QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    provisionExpired();
    if (Issue *existing = findByIdentity(issue.identity())) {
        *existing = issue;
        emit issueUpdated();
        return true;
    }
    insertImmediate(issue);
    return false;
}

int IssueDb::removeByUrl(QString url)
{
    QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    const QUrl expected(url);
    int removed = 0;
    int activeRemoved = 0;

    for (auto it = m_issues.begin(); it != m_issues.end();) {
        if (it->field30 == expected) {
            it = m_issues.erase(it);
            ++removed;
            ++activeRemoved;
        } else {
            ++it;
        }
    }
    if (activeRemoved > 0)
        emit issueUpdated();
    for (auto it = m_pending.begin(); it != m_pending.end();) {
        if (it.value().field30 == expected) {
            it = m_pending.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    // gui.exe:0x1401287F0 expires pending entries after both removal passes.
    provisionExpired();
    return removed;
}

int IssueDb::removeAll(std::function<bool(Issue)> func)
{
    QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    int removed = 0;
    int activeRemoved = 0;

    for (auto it = m_issues.begin(); it != m_issues.end();) {
        if (func(*it)) {
            it = m_issues.erase(it);
            ++removed;
            ++activeRemoved;
        } else {
            ++it;
        }
    }
    if (activeRemoved > 0)
        emit issueUpdated();
    for (auto it = m_pending.begin(); it != m_pending.end();) {
        if (func(it.value())) {
            it = m_pending.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    // gui.exe:0x140127E20 also expires after its active and pending passes.
    provisionExpired();
    return removed;
}

void IssueDb::provision()
{
    QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    const auto values = m_pending.values();
    for (const Issue &issue : values)
        insertImmediate(issue);
    m_pending.clear();
}
