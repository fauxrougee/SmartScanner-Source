#pragma once

#include <QString>
#include <QUrl>

// gui.exe:0x14014F450 / 0x140150310 / 0x14014F650.
// Stateless URL-root comparison used by Custom404Detector URL history.
[[nodiscard]] int custom404PathSlashCount(const QUrl &url);
[[nodiscard]] QString custom404PathRoot(const QUrl &url, int depth);
[[nodiscard]] bool custom404SamePathRoot(const QUrl &first, const QUrl &second,
                                         bool directoryAdjustment);
[[nodiscard]] QString custom404ParentDirectoryKey(const QUrl &url);
