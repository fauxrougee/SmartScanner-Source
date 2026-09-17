#pragma once

#include "httprequestrawpacket.h"

#include <QSharedPointer>
#include <QString>
#include <QUrl>

// gui.exe:0x14006D3A0. Builds the item that the native caller inserts into
// FileList with mask 0x1c. The source meaning of field60 is unrecovered.
[[nodiscard]] QSharedPointer<urlItem> makeDirectoryRootRequest(
    const QString &target, const QUrl &referer, qint64 field60);
