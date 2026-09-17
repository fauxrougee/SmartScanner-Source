#pragma once

#include "httprequestrawpacket.h"

#include <QList>
#include <QSharedPointer>

// Clean-room labels for gui.exe:0x140160530 and 0x140160320. The native
// stream dispatches by the virtual type string, then calls the item stream
// slot. The only accepted concrete types are urlItem and HtmlForm.
using RequestItemPointer = QSharedPointer<HttpRequestItem>;

QDataStream &writeRequestItem(QDataStream &stream, const RequestItemPointer &item);
QDataStream &readRequestItem(QDataStream &stream, RequestItemPointer &item);

QDataStream &writeRequestItems(QDataStream &stream, const QList<RequestItemPointer> &items);
QDataStream &readRequestItems(QDataStream &stream, QList<RequestItemPointer> &items);
