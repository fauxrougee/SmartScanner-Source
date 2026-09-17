#pragma once

#include "issue.h"

#include <QList>
#include <QDataStream>
#include <QMultiMap>
#include <QObject>
#include <QRecursiveMutex>
#include <QSet>
#include <QUrl>

#include <functional>

// Recovered QObject API and collection transitions from gui.exe IssueDb.
// Unrecovered UI/logging-only members are intentionally not synthesized.
class IssueDb final : public QObject
{
    Q_OBJECT

public:
    explicit IssueDb(QObject *parent = nullptr);

    // gui.exe:0x1400E2590 / 0x1400E1930, on the live IssueDb instance.
    friend QDataStream &operator<<(QDataStream &stream, const IssueDb &db);
    friend QDataStream &operator>>(QDataStream &stream, IssueDb &db);

    bool add(Issue issue, bool addPending);
    bool add(Issue issue);
    bool addOrUpdate(Issue issue);
    int removeByUrl(QString url);
    int removeAll(std::function<bool(Issue)> func);
    void provision();

    [[nodiscard]] const QList<Issue> &issues() const noexcept { return m_issues; }
    [[nodiscard]] const QMultiMap<qint64, Issue> &pendingIssues() const noexcept { return m_pending; }

signals:
    void newIssueAdded(Issue issue);
    void issueUpdated();

private:
    void provisionExpired();
    void provision(qint64 timestamp);
    bool containsIdentity(quint64 identity);
    Issue *findByIdentity(quint64 identity);
    void insertImmediate(const Issue &issue);

    QRecursiveMutex m_mutex;
    QList<Issue> m_issues;
    QMultiMap<qint64, Issue> m_pending;
    qint64 m_pendingIntervalMs = 600000;
    // Native +0x2c8: preserve loaded data; the producer is not recovered yet.
    QSet<QUrl> m_field2C8;
};
