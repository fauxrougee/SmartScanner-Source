#pragma once

#include <QHash>
#include <QSet>
#include <QUrl>

// gui.exe RTTI names this object FileCountConstrain. Its stream form begins
// after the native vtable pointer and is represented by FileListFilterState.
class FileCountConstrain {
public:
    FileCountConstrain();

    // gui.exe:0x140160870, virtual slot 0. This records directory component
    // hashes while enforcing the configured per-directory limits.
    virtual bool acceptAndRecord(const QUrl &url);

    // gui.exe:0x140160630. Query-only; it does not mutate the constraint.
    [[nodiscard]] bool contains(const QUrl &url) const;

    quint32 field08 = 999;
    quint32 field0C = 999;
    quint32 field10 = 999;
    QHash<quint32, quint32> field18;
    QHash<quint64, QSet<quint64>> field20;

protected:
    [[nodiscard]] static QUrl normalizeForConstraint(const QUrl &url, quint8 flags);
    [[nodiscard]] static qsizetype pathDepth(const QUrl &url);
    [[nodiscard]] static QString directoryUrl(const QUrl &url, qsizetype depth);
    [[nodiscard]] static QString pathComponent(const QUrl &url, qsizetype depth);
};
