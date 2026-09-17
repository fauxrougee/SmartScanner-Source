#pragma once

#include <QPair>
#include <QSet>
#include <QUrl>

// gui.exe:0x140162A90. Returns true when at least one query-parameter name
// is absent from the FileList state set supplied by the caller.
[[nodiscard]] bool fileListHasUnseenQueryName(
    const QSet<quint64> &seenNames, const QUrl &url,
    const QList<QPair<QString, QString>> &packetQueryItems);

// gui.exe:0x140162F00. Determines whether a name/value pair participates in
// the reduced query signatures built by the FileList rate limiter.
[[nodiscard]] bool fileListRetainsQueryItemForRateLimit(
    const QPair<QString, QString> &item);
