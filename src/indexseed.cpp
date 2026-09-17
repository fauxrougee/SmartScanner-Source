#include "indexseed.h"

QSharedPointer<urlItem> makeIndexSeedRequest(const QString &target,
                                              const QUrl &referer,
                                              qint64 field60)
{
    // gui.exe:0x140072E80
    auto item = QSharedPointer<urlItem>::create(target, 1, QByteArray());
    item->setStandardHeader(HttpRequestItem::StandardHeader::Referer,
                            referer.toString().toUtf8());
    item->field60 = field60;
    item->field6C = 1;
    item->field70 = QStringLiteral("?!index!?");
    item->field68 = 489;
    item->field50 = 6;
    return item;
}
