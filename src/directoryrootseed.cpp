#include "directoryrootseed.h"

QSharedPointer<urlItem> makeDirectoryRootRequest(const QString &target,
                                                  const QUrl &referer,
                                                  qint64 field60)
{
    // gui.exe:0x14006D3A0. The native creates urlItem(target, 1, {}), stores
    // the caller/config-derived +0x60 value, copies referer as UTF-8, assigns
    // the literal +0x68 value 489 and request kind 2 at +0x88.
    auto item = QSharedPointer<urlItem>::create(target, 1, QByteArray());
    item->field60 = field60;
    item->setStandardHeader(HttpRequestItem::StandardHeader::Referer,
                            referer.toString().toUtf8());
    item->field68 = 489;
    item->field88 = 2;
    return item;
}
