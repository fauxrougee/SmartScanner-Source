#pragma once

#include <QByteArray>
#include <QHash>
#include <QUrl>

// gui.exe:0x14014BE50 / 0x14014F3B0. The native map is keyed only by the
// qHash of a canonicalized parent-directory string.
[[nodiscard]] quint64 custom404DirectoryBodyKey(const QUrl &url);
[[nodiscard]] QByteArray custom404LookupDirectoryBody(
    const QHash<quint64, QByteArray> &bodies, const QUrl &url);
