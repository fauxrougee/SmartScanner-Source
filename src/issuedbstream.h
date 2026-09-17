#pragma once

#include "issue.h"

#include <QDataStream>
#include <QList>
#include <QMultiMap>
#include <QSet>
#include <QUrl>

// Recovered serial state at gui.exe IssueDb offsets +0x2a0 through +0x2c8.
// This deliberately excludes QObject, locking, logging, and live API methods.
struct IssueDbStreamState
{
    QList<Issue> field2A0;
    QMultiMap<qint64, Issue> field2B8;
    qint64 field2C0 = 600000;
    QSet<QUrl> field2C8;
};

QDataStream &operator<<(QDataStream &stream, const IssueDbStreamState &state);
QDataStream &operator>>(QDataStream &stream, IssueDbStreamState &state);
