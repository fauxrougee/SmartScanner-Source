#pragma once

#include <QList>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>

// gui.exe:0x1400B6AC0. The RobotTxt constructor creates both expressions
// with PatternOptions 5: CaseInsensitiveOption | MultilineOption.
[[nodiscard]] const QRegularExpression &robotTxtResourceExpression();
[[nodiscard]] const QRegularExpression &robotTxtSitemapExpression();

// gui.exe:0x1400B6320. Captures group 1, trims it, rejects empty, '*' and '$'
// values, resolves the result through 0x140150490, and inserts it into a set.
// The native code subsequently compares the resulting URLs with FileList; that
// separate comparison and request scheduling are intentionally not modeled here.
[[nodiscard]] QSet<QUrl> robotTxtResourceLocations(const QUrl &sourceUrl,
                                                    const QString &responseBody);

// gui.exe:0x1400B5EE0. This is the parse-and-resolve portion before the native
// FileList insertion and QNetworkRequest scheduling.
[[nodiscard]] QList<QUrl> robotTxtSitemapLocations(const QUrl &sourceUrl,
                                                    const QString &responseBody);
