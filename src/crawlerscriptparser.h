#pragma once

#include <QByteArray>
#include <QList>
#include <QRegularExpression>
#include <QUrl>

// Deterministic script slice of gui.exe:0x1400718F0. The caller's FileList
// insertion and callback dispatch remain separate from this extraction.
struct CrawlerScriptParseResult {
    QList<QUrl> sourceLocations;
    QByteArray fingerprint;
};

[[nodiscard]] const QRegularExpression &crawlerScriptElementExpression();
[[nodiscard]] const QRegularExpression &crawlerAnalyticsScriptExpression();
[[nodiscard]] const QRegularExpression &crawlerScriptTypeExpression();
[[nodiscard]] const QRegularExpression &crawlerScriptSourceExpression();
[[nodiscard]] const QRegularExpression &crawlerScriptEventExpression();

[[nodiscard]] CrawlerScriptParseResult crawlerParseScripts(const QUrl &responseUrl,
                                                            const QString &document);
