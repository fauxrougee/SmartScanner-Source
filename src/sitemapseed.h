#pragma once

#include "httprequestrawpacket.h"

#include <QSharedPointer>
#include <QString>
#include <QUrl>

// gui.exe:0x1400B3AF0. These helpers model only sitemap seed construction;
// network dispatch in the native routine remains a separate component.
[[nodiscard]] QUrl sitemapSeedUrl(const QString &target);
[[nodiscard]] QSharedPointer<urlItem> makeSitemapSeedRequest(
    const QString &target, qint64 field60);

// gui.exe:0x1400B61A0. Builds an item for a URL extracted from sitemap data.
// The native caller inserts it into FileList with mask 0x00.
[[nodiscard]] QSharedPointer<urlItem> makeSitemapDiscoveredRequest(
    const QUrl &url, qint32 depth, qint64 field60);
