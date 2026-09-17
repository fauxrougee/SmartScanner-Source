#pragma once

#include "httprequestrawpacket.h"

#include <QSharedPointer>
#include <QString>
#include <QUrl>

// gui.exe:0x140072E80. Native index-discovery item builder; the caller inserts
// the result into FileList with mask 0x1c.
[[nodiscard]] QSharedPointer<urlItem> makeIndexSeedRequest(
    const QString &target, const QUrl &referer, qint64 field60);
