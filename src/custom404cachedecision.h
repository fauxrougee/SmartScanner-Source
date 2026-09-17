#pragma once

#include <QByteArray>
#include <QHash>
#include <QStringList>
#include <QUrl>

// gui.exe:0x14014F1A0 after native response-body extraction. Return values are
// intentionally the original classifier values: -2, 0, 1, or 3.
[[nodiscard]] int custom404CachedBodyDecision(
    const QByteArray &responseBody, const QUrl &url, bool matchesRetainedBody,
    const QHash<quint64, QByteArray> &directoryBodies,
    const QStringList &storedScopes);
