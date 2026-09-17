#include "filelistquerystate.h"

#include "filelistqueryfilter.h"
#include "urlnormalizer.h"

#include <QUrlQuery>
#include <QStringList>
#include <QStringView>
#include <utility>

QDataStream &operator<<(QDataStream &stream, const FileListQueryState &state)
{
    // gui.exe:0x1400E2A15/21/2D: hash, tracked-key list, name set.
    stream << state.m_counters << state.m_trackedCounterKeys << state.m_seenNames;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, FileListQueryState &state)
{
    // gui.exe:0x1400E1DE3/EF/FB; directly restores the three containers.
    stream >> state.m_counters >> state.m_trackedCounterKeys >> state.m_seenNames;
    return stream;
}

namespace {

using QueryItem = QPair<QString, QString>;

quint64 stringHash(const QString &value, size_t seed)
{
    return qHash(QStringView(value), seed);
}

QString queryNames(const QList<QueryItem> &urlItems,
                   const QList<QueryItem> &packetItems)
{
    // gui.exe:0x140163500
    QStringList result;
    for (const QueryItem &item : urlItems)
        result.append(item.first);
    if (!packetItems.isEmpty())
        result.append(QStringLiteral("^"));
    for (const QueryItem &item : packetItems)
        result.append(item.first);
    return QStringLiteral("?") + result.join(QLatin1Char('&'));
}

QString queryNamesExcluding(const QList<QueryItem> &urlItems,
                            const QList<QueryItem> &packetItems,
                            const QueryItem &selected,
                            bool selectedIsPacketItem, bool applyItemPredicate)
{
    // gui.exe:0x140163790.  A standalone "^" separates URL and packet
    // parameters even if the optional predicate removes every packet item.
    QStringList result;
    for (const QueryItem &item : urlItems) {
        if (!selectedIsPacketItem && item == selected)
            continue;
        if (!applyItemPredicate || fileListRetainsQueryItemForRateLimit(item))
            result.append(item.first + QLatin1Char('=') + item.second);
    }
    if (!packetItems.isEmpty())
        result.append(QStringLiteral("^"));
    for (const QueryItem &item : packetItems) {
        if (selectedIsPacketItem && item == selected)
            continue;
        if (!applyItemPredicate || fileListRetainsQueryItemForRateLimit(item))
            result.append(item.first + QLatin1Char('=') + item.second);
    }
    return result.isEmpty() ? QString()
        : QStringLiteral("?") + result.join(QLatin1Char('&'));
}

void recordQueryName(QSet<quint64> &seenNames, const QueryItem &item,
                     const QString &host, bool packetItem)
{
    // The insertion path is duplicated inline in gui.exe:0x140161620 rather
    // than calling the membership helper at 0x140162A90.
    const QString key = packetItem ? QStringLiteral("%1?%2^").arg(item.first, host)
                                   : QStringLiteral("%1?%2").arg(item.first, host);
    seenNames.insert(stringHash(key, 1001));
}

} // namespace

bool FileListQueryState::incrementAndTrack(quint64 key, qint32 limit)
{
    // gui.exe:0x140163240, using its lookup-or-insert helper at 0x140160F20.
    qint32 &value = m_counters[key];
    if (value >= limit)
        return false;
    ++value;
    m_trackedCounterKeys.append(key); // gui.exe:0x1400F21A0
    return true;
}

void FileListQueryState::rollbackTrackedCounters(bool rollback)
{
    // gui.exe:0x1401633E0.  A successful call deliberately retains the
    // tracked keys; a later rollback decrements every tracked counter.
    if (!rollback)
        return;
    for (quint64 key : std::as_const(m_trackedCounterKeys))
        --m_counters[key];
    m_trackedCounterKeys.clear();
}

bool FileListQueryState::acceptParameter(const QUrl &url,
    const QPair<QString, QString> &selected,
    const QList<QPair<QString, QString>> &packetItems, bool selectedIsPacketItem)
{
    // gui.exe:0x1401610A0. Hash order and seeds are preserved; rollback
    // applies to the accumulated tracked list, not just this invocation.
    const QString canonical = UrlNormalizer::canonical(url, 46);
    const QList<QueryItem> urlItems = QUrlQuery(url).queryItems();
    QString name = selected.first;
    if (selectedIsPacketItem)
        name += QLatin1Char('^');
    const QString prefix = name + QLatin1Char('@') + canonical;
    const quint64 reducedKey = stringHash(prefix + queryNamesExcluding(
        urlItems, packetItems, selected, selectedIsPacketItem, true), 0);
    const quint64 namesKey = stringHash(prefix + queryNames(urlItems, packetItems), 0);
    const quint64 valueKey = stringHash(name + QLatin1Char('=') + selected.second, 0);
    const quint64 nameKey = stringHash(name, 0);
    if (fileListRetainsQueryItemForRateLimit(selected)
        && !incrementAndTrack(stringHash(canonical + QLatin1Char('?') + name, 0), 1)) {
        rollbackTrackedCounters(true);
        return false;
    }
    const bool accepted = incrementAndTrack(reducedKey, 1)
        && incrementAndTrack(namesKey, 3)
        && incrementAndTrack(valueKey, 10)
        && incrementAndTrack(nameKey, 25);
    rollbackTrackedCounters(!accepted);
    return accepted;
}

bool FileListQueryState::accept(const QUrl &url,
                                const QList<QPair<QString, QString>> &packetQueryItems)
{
    // gui.exe:0x140161620
    const QList<QueryItem> urlItems = QUrlQuery(url).queryItems();
    QUrlQuery packetQuery;
    packetQuery.setQueryItems(packetQueryItems);
    const QString canonicalUrl = UrlNormalizer::canonical(url, 46);

    const QString baseSignature = canonicalUrl + QLatin1Char('?')
        + QUrlQuery(url).toString() + QLatin1Char('^') + packetQuery.toString();
    if (!incrementAndTrack(stringHash(baseSignature, 1000), 1))
        return false;

    if (!urlItems.isEmpty()
        && !incrementAndTrack(stringHash(QStringLiteral("__?") + canonicalUrl, 1000), 100))
        return false;
    if (!packetQueryItems.isEmpty()
        && !incrementAndTrack(stringHash(QStringLiteral("__@") + canonicalUrl, 1000), 100))
        return false;

    const qint32 perItemLimit = qMax(10 / qMax(urlItems.size() + packetQueryItems.size(), 1), 1);
    const QString host = url.host(QUrl::FullyDecoded);
    const QString allNames = queryNames(urlItems, packetQueryItems);
    bool acceptedAtLeastOne = false;
    bool rollback = true;

    for (const QueryItem &item : urlItems) {
        recordQueryName(m_seenNames, item, host, false);

        const QString completeSignature = item.first + QLatin1Char('=') + item.second
            + QLatin1Char('@') + canonicalUrl + allNames;
        if (!incrementAndTrack(stringHash(completeSignature, 0), perItemLimit)) {
            rollbackTrackedCounters(true);
            return false;
        }

        const QString reducedSignature = item.first + QLatin1Char('@') + canonicalUrl
            + queryNamesExcluding(urlItems, packetQueryItems, item, false, false);
        if (!incrementAndTrack(stringHash(reducedSignature, 0), perItemLimit)) {
            if (!acceptedAtLeastOne) {
                rollbackTrackedCounters(true);
                return false;
            }
        } else {
            acceptedAtLeastOne = true;
        }
        rollback = false;
    }

    for (const QueryItem &item : packetQueryItems) {
        recordQueryName(m_seenNames, item, host, true);

        const QString completeSignature = item.first + QLatin1Char('=') + item.second
            + QStringLiteral("^@") + canonicalUrl + allNames;
        if (!incrementAndTrack(stringHash(completeSignature, 0), perItemLimit)) {
            rollbackTrackedCounters(true);
            return false;
        }

        const QString reducedSignature = item.first + QStringLiteral("^@") + canonicalUrl
            + queryNamesExcluding(urlItems, packetQueryItems, item, true, true);
        if (!incrementAndTrack(stringHash(reducedSignature, 0), perItemLimit)) {
            if (!acceptedAtLeastOne) {
                rollbackTrackedCounters(true);
                return false;
            }
        } else {
            acceptedAtLeastOne = true;
        }
        rollback = false;
    }

    rollbackTrackedCounters(rollback);
    return acceptedAtLeastOne;
}

const QSet<quint64> &FileListQueryState::seenNames() const noexcept
{
    return m_seenNames;
}
