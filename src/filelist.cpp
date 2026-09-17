#include "filelist.h"

#include "filelistqueryfilter.h"
#include "fileliststream.h"
#include "filelisturlheuristic.h"

#include <QUrlQuery>

QDataStream &operator<<(QDataStream &stream, const FileList &list)
{
    // gui.exe:0x1400E29F2-0x1400E2B22. Configuration is not part of this
    // component payload; Scanner restores it separately from ScanConfig.
    stream << list.field18 << list.field34 << list.field50 << list.field90
           << list.fieldB0 << list.fieldD8
           << list.field118 << list.field11C << list.field120 << list.field124
           << list.field128 << list.field12C << list.field130 << list.field134;
    return writeRequestItems(stream, list.field78);
}

QDataStream &operator>>(QDataStream &stream, FileList &list)
{
    // gui.exe:0x1400E1DBF-0x1400E1EB5. No add()/validation pass: serials,
    // identities and rejection counters retain their on-disk values.
    stream >> list.field18 >> list.field34 >> list.field50 >> list.field90
           >> list.fieldB0 >> list.fieldD8
           >> list.field118 >> list.field11C >> list.field120 >> list.field124
           >> list.field128 >> list.field12C >> list.field130 >> list.field134;
    return readRequestItems(stream, list.field78);
}

FileList::FileList(QObject *parent)
    : QObject(parent)
{
    // gui.exe:0x14011B360 initializes an empty QSet, default regular
    // expression, zero maximum, depth -1, empty expression lists and both
    // FileCountConstrain instances before creating scanner.crawler logging.
}

qsizetype FileList::size() const
{
    // gui.exe:0x14011BC80
    const QReadLocker locker(&m_lock);
    return field78.size();
}

RequestItemPointer FileList::find(
    const std::function<bool(const RequestItemPointer &)> &predicate) const
{
    // gui.exe:0x14011BD30
    const QReadLocker locker(&m_lock);
    for (const RequestItemPointer &item : field78) {
        if (predicate(item))
            return item;
    }
    return {};
}

QList<RequestItemPointer> FileList::itemsFrom(qsizetype offset, qsizetype maximum)
{
    // gui.exe:0x14011C0A0 / 0x14011C150.  The native path holds a read lock,
    // constrains the range to the queue, records the high-water endpoint, and
    // returns a shared-pointer copy of that slice.
    const QReadLocker lock(&m_lock);
    const qsizetype start = qBound<qsizetype>(0, offset, field78.size());
    const qsizetype count = qMax<qsizetype>(0,
        qMin(maximum, field78.size() - start));
    field90 = qMax(field90, start + count);
    return field78.mid(start, count);
}

bool FileList::matchesScopeAndExclusions(const QUrl &url) const
{
    // gui.exe:0x14011C4D0
    const QReadLocker locker(&m_lock);
    // The scope path passes ComponentFormattingOption 0x200000, which is
    // EncodeUnicode in Qt 6. URL exclusions below use RemoveFragment.
    const QString scopeSerialized = url.toString(QUrl::EncodeUnicode);
    if (!field20.match(scopeSerialized).hasMatch())
        return false;

    const QString serialized = url.toString(QUrl::RemoveFragment);

    for (const QRegularExpression &expression : field98) {
        if (expression.match(serialized).hasMatch())
            return false;
    }

    const QString fileName = url.fileName(QUrl::FullyDecoded);
    for (const QRegularExpression &expression : field38) {
        if (expression.match(fileName).hasMatch())
            return false;
    }
    return true;
}

bool FileList::matchesScope(const QUrl &url) const
{
    // gui.exe:0x14014A0A0. Unlike matchesScopeAndExclusions(), this callback
    // gate does not consult either URL or filename exclusions.
    const QReadLocker locker(&m_lock);
    return field20.match(url.toString(QUrl::EncodeUnicode)).hasMatch();
}

QVariantMap FileList::skippedSummary() const
{
    // gui.exe:0x14011C360 returns `this + 0x118`; 0x1400E9470 assigns the
    // following literal reason labels to those eight consecutive integers.
    const QReadLocker locker(&m_lock);
    const quint64 total = static_cast<quint64>(field118) + field11C + field120
        + field124 + field128 + field12C + field130 + field134;
    return {
        {QStringLiteral("total"), total},
        {QStringLiteral("reasons"), QVariantMap{
            {QStringLiteral("Outside scan scope"), field120},
            {QStringLiteral("URL limit reached"), field118},
            {QStringLiteral("Crawl depth limit reached"), field11C},
            {QStringLiteral("Content page limit reached"), field12C},
            {QStringLiteral("Directory file limit reached"), field134},
            {QStringLiteral("Query variation limit reached"), field130},
            {QStringLiteral("Excluded by filename rule"), field128},
            {QStringLiteral("Excluded by URL rule"), field124}
        }}
    };
}

bool FileList::validateAndRecord(const QSharedPointer<urlItem> &item, quint8 flags)
{
    // gui.exe:0x14011B800. The write lock covers identity, rate and
    // FileCountConstrain state, as well as all rejection counters.
    const QWriteLocker locker(&m_lock);
    const quint64 identity = requestItemIdentity(*item);
    if (field18.contains(identity))
        return false;
    // Native order: rejected identities remain recorded.
    field18.insert(identity);

    if ((flags & 0x01) != 0 && field28 != 0 && field18.size() - 1 >= field28) {
        ++field118;
        return false;
    }
    if ((flags & 0x02) != 0 && field30 > -1 && item->field6C > field30) {
        ++field11C;
        return false;
    }

    const QUrl url = item->url();
    if ((flags & 0x04) != 0
        && !field20.match(url.toString(QUrl::EncodeUnicode)).hasMatch()) {
        ++field120;
        return false;
    }
    if ((flags & 0x08) != 0) {
        const QString serialized = url.toString(QUrl::RemoveFragment);
        for (const QRegularExpression &expression : field98) {
            if (expression.match(serialized).hasMatch()) {
                ++field124;
                return false;
            }
        }
    }
    if ((flags & 0x10) != 0) {
        const QString fileName = url.fileName(QUrl::FullyDecoded);
        for (const QRegularExpression &expression : field38) {
            if (expression.match(fileName).hasMatch()) {
                ++field128;
                return false;
            }
        }
    }

    const QString packetQueryText = QString::fromUtf8(item->field28Copy());
    QUrlQuery packetQuery(packetQueryText);
    const QList<QPair<QString, QString>> packetItems = packetQuery.queryItems();
    if ((flags & 0x80) != 0 && item->field6C > 1
        && !fileListHasUnseenQueryName(field50.seenNames(), url, packetItems)
        && fileListUrlHeuristic(url)
        && (fieldD8.contains(url) || !fieldD8.acceptAndRecord(url))) {
        ++field12C;
        return false;
    }
    if ((flags & 0x20) != 0 && (url.hasQuery() || !packetQueryText.isEmpty())
        && !field50.accept(url, packetItems)) {
        ++field130;
        return false;
    }
    if ((flags & 0x40) != 0 && !fieldB0.acceptAndRecord(url)) {
        ++field134;
        return false;
    }
    return true;
}

quint32 FileList::add(const QSharedPointer<urlItem> &item, quint8 flags)
{
    // gui.exe:0x14011B610
    if (!item || !validateAndRecord(item, flags))
        return 0;

    const QWriteLocker locker(&m_lock);
    item->field58 = ++field34;
    field78.append(item);
    return item->field58;
}
