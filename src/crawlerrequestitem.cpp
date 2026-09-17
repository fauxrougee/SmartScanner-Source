#include "crawlerrequestitem.h"

QSharedPointer<urlItem> makeCrawlerRequest(const QUrl &location, const QUrl &referer,
                                            qint32 responseAttribute1004,
                                            qint32 sourceRequestKind,
                                            qint32 sourceAttribute1011,
                                            qint64 sourceAttribute1012)
{
    // gui.exe:0x140070C36 through 0x140070CAF.
    auto item = QSharedPointer<urlItem>::create(location.toString(), 1, QByteArray());

    // gui.exe:0x140070A78 through 0x140070A9A.
    item->setStandardHeader(HttpRequestItem::StandardHeader::Referer,
                            referer.toString().toUtf8());

    // gui.exe:0x140070AF3. The source is QNetworkRequest attribute key 1004.
    item->field6C = responseAttribute1004 + 1;

    // gui.exe:0x140070B10 through 0x140070BAC. Attribute 1011 is tested as a
    // bit mask by 0x14013ED60; when bit 2 is set, field60 receives attribute
    // 1012 (read by 0x14013C220). When bit 4 is set, field68 receives the
    // 1011 value itself (read by 0x14013B280).
    item->field88 = 0;
    if (sourceRequestKind != 1)
        ++item->field88;
    if (location.hasQuery())
        ++item->field88;
    item->field60 = (sourceAttribute1011 & 2) == 2 ? sourceAttribute1012 : 2;
    if ((sourceAttribute1011 & 4) == 4)
        item->field68 = sourceAttribute1011;
    return item;
}
