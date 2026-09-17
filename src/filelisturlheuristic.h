#pragma once

#include <QUrl>

// gui.exe:0x14014FA50. Original source naming was not retained. The optional
// output receives true only for the native extensionless-file-name fast path.
[[nodiscard]] bool fileListUrlHeuristic(const QUrl &url,
                                        bool *extensionlessFileName = nullptr);
