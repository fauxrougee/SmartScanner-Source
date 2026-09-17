#pragma once

#include <QList>
#include <QRegularExpression>
#include <QUrl>

// gui.exe:0x14006C690. Both expressions use QRegularExpression pattern option 1
// (CaseInsensitiveOption) in the shared CrawlerParser constructor.
[[nodiscard]] const QRegularExpression &crawlerXmlSitemapLocationExpression();
[[nodiscard]] const QRegularExpression &crawlerRejectedLocationExpression();

// gui.exe:0x14006DA40. The native predicate is evaluated on QUrl::toString()
// after location resolution.
[[nodiscard]] bool crawlerAcceptsResolvedLocation(const QUrl &location);

// gui.exe:0x1400718F0. This is only the XML sitemap capture, resolve, and
// rejection path. Native FileList insertion and follow-up scheduling occur
// after this point and are deliberately not represented here.
[[nodiscard]] QList<QUrl> crawlerXmlSitemapLocations(const QUrl &sourceUrl,
                                                       const QString &contentType,
                                                       const QString &responseBody);
