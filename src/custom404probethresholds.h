#pragma once

#include <QString>
#include <QUrl>

// gui.exe lambda callbacks installed by 0x14014E1A0 at thresholds 5, 10, 15.
[[nodiscard]] bool custom404ProbeMatchesPathRoot(const QString &candidateUrl,
                                                  const QString &expectedRoot);
[[nodiscard]] bool custom404ProbeMatchesHost(const QString &candidateUrl,
                                              const QUrl &expectedUrl);
[[nodiscard]] constexpr bool custom404ProbeMatchesUnconditionally() { return true; }
