#pragma once

#include "filecountconstrain.h"
#include "requestitemstream.h"

#include <QHash>
#include <QList>
#include <QSet>

// Clean-room stream-facing name for FileCountConstrain's persisted fields.
// The native stream begins after its vtable pointer.
using FileListFilterState = FileCountConstrain;

QDataStream &operator<<(QDataStream &stream, const FileListFilterState &state);
QDataStream &operator>>(QDataStream &stream, FileListFilterState &state);

struct FileListStreamState {
    QSet<qint64> field18;
    quint32 field34 = 0;
    QHash<qint64, quint32> field50;
    QList<qint64> field58;
    QSet<qint64> field70;
    qint64 field90 = 0;
    FileListFilterState fieldB0;
    FileListFilterState fieldD8;
    quint32 field118 = 0;
    quint32 field11C = 0;
    quint32 field120 = 0;
    quint32 field124 = 0;
    quint32 field128 = 0;
    quint32 field12C = 0;
    quint32 field130 = 0;
    quint32 field134 = 0;
    QList<RequestItemPointer> field78;
};

QDataStream &operator<<(QDataStream &stream, const FileListStreamState &state);
QDataStream &operator>>(QDataStream &stream, FileListStreamState &state);
