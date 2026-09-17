#pragma once

#include "filecountconstrain.h"
#include "filelistquerystate.h"
#include "requestitemstream.h"

#include <QList>
#include <QLoggingCategory>
#include <QReadWriteLock>
#include <QRegularExpression>
#include <QSet>
#include <QVariantMap>

#include <functional>

// gui.exe:0x14011B360. The insertion/validation method is intentionally kept
// separate until every flags branch has a source transcription.
class FileList : public QObject {
public:
    explicit FileList(QObject *parent = nullptr);

    // Live FileList slice of gui.exe:0x1400E2910 / 0x1400E1CA0.
    friend QDataStream &operator<<(QDataStream &stream, const FileList &list);
    friend QDataStream &operator>>(QDataStream &stream, FileList &list);

    // gui.exe:0x14011BC80
    [[nodiscard]] qsizetype size() const;

    // gui.exe:0x14011BD30
    [[nodiscard]] RequestItemPointer find(
        const std::function<bool(const RequestItemPointer &)> &predicate) const;

    // gui.exe:0x14011C0A0.  This is a protected read-only slice: it does not
    // remove entries from FileList.  The caller's cursor decides which items
    // are newly scheduled.
    [[nodiscard]] QList<RequestItemPointer> itemsFrom(qsizetype offset,
                                                       qsizetype maximum);

    // gui.exe:0x14011C4D0
    [[nodiscard]] bool matchesScopeAndExclusions(const QUrl &url) const;

    // gui.exe:0x14014A0A0 serialises the URL with EncodeUnicode and tests
    // only FileList's scope regular expression. Scanner's response callback
    // deliberately uses this narrower predicate before dispatching work.
    [[nodiscard]] bool matchesScope(const QUrl &url) const;

    // gui.exe:0x14011C360 and Scanner's update-map producer 0x1400E9470.
    // The layout is FileList+0x118: eight rejection counters mapped to the
    // WebChannel's crawler_skipped object.
    [[nodiscard]] QVariantMap skippedSummary() const;

    // gui.exe:0x14011B610. Returns zero on rejection; otherwise returns the
    // serial assigned to urlItem::field58. HtmlForm derives from urlItem.
    [[nodiscard]] quint32 add(const QSharedPointer<urlItem> &item, quint8 flags);

    // Observed configuration/state fields. Their original public setter names
    // have not been recovered from the binary.
    QRegularExpression field20;
    quint64 field28 = 0;
    qint32 field30 = -1;
    QList<QRegularExpression> field38;
    QList<QRegularExpression> field98;
    FileCountConstrain fieldB0;
    FileCountConstrain fieldD8;

private:
    mutable QReadWriteLock m_lock;
    QSet<quint64> field18;
    quint32 field34 = 0;
    FileListQueryState field50;
    QList<RequestItemPointer> field78;
    // gui.exe:0x14011C0A0 records the greatest requested slice endpoint at
    // native FileList+0x90.
    qsizetype field90 = 0;
    QLoggingCategory field100{"scanner.crawler"};
    quint32 field118 = 0;
    quint32 field11C = 0;
    quint32 field120 = 0;
    quint32 field124 = 0;
    quint32 field128 = 0;
    quint32 field12C = 0;
    quint32 field130 = 0;
    quint32 field134 = 0;

    [[nodiscard]] bool validateAndRecord(const QSharedPointer<urlItem> &item,
                                         quint8 flags);
};
