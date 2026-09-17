#pragma once

#include <QHash>
#include <QDataStream>
#include <QList>
#include <QPair>
#include <QSet>
#include <QUrl>

// Clean-room transcription of the non-QObject state constructed by
// gui.exe:0x140161070 and used by gui.exe:0x140161620.  It is the query-rate
// state held by FileList; FileList insertion remains separate until its whole
// flag-mask validation path is recovered.
class FileListQueryState {
public:
    [[nodiscard]] bool accept(const QUrl &url,
                              const QList<QPair<QString, QString>> &packetQueryItems);
    // gui.exe:0x1401610A0, also used by the state embedded in Manipulator.
    [[nodiscard]] bool acceptParameter(const QUrl &url,
        const QPair<QString, QString> &selected,
        const QList<QPair<QString, QString>> &packetItems, bool selectedIsPacketItem);

    [[nodiscard]] const QSet<quint64> &seenNames() const noexcept;

    // Embedded FileList+0x50, gui.exe:0x1400E2A15/21/2D and inverse reader.
    friend QDataStream &operator<<(QDataStream &stream, const FileListQueryState &state);
    friend QDataStream &operator>>(QDataStream &stream, FileListQueryState &state);

private:
    [[nodiscard]] bool incrementAndTrack(quint64 key, qint32 limit);
    void rollbackTrackedCounters(bool rollback);

    QHash<quint64, qint32> m_counters;
    QList<quint64> m_trackedCounterKeys;
    QSet<quint64> m_seenNames;
};
