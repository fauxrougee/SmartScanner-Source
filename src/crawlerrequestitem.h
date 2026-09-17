#pragma once

#include "httprequestrawpacket.h"

#include <QSharedPointer>

// gui.exe:0x140070C00 and the default (no native configuration override)
// branch of 0x140070A30. The raw parameter spelling preserves the observed
// QNetworkRequest attribute key rather than assigning an unproven meaning.
[[nodiscard]] QSharedPointer<urlItem> makeCrawlerRequest(
    const QUrl &location, const QUrl &referer, qint32 responseAttribute1004,
    qint32 sourceRequestKind, qint32 sourceAttribute1011 = 0,
    qint64 sourceAttribute1012 = 0);
