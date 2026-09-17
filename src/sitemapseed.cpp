#include "sitemapseed.h"

QUrl sitemapSeedUrl(const QString &target)
{
    // gui.exe:0x1400B3AF0
    QUrl url = QUrl::fromUserInput(target);
    url.setPath(QStringLiteral("/sitemap.xml"), QUrl::DecodedMode);
    url.setQuery(QString());
    url.setFragment(QString());
    return url;
}

QSharedPointer<urlItem> makeSitemapSeedRequest(const QString &target, qint64 field60)
{
    // gui.exe:0x1400B3AF0. The native receives field60 through an unrecovered
    // virtual Crawler/Sitemap method, so its raw offset name is retained.
    const QUrl url = sitemapSeedUrl(target);
    auto item = QSharedPointer<urlItem>::create(url.toString(), 1, QByteArray());
    item->field60 = field60;
    item->field6C = 1;
    item->field94 = true;
    return item;
}

QSharedPointer<urlItem> makeSitemapDiscoveredRequest(const QUrl &url, qint32 depth,
                                                      qint64 field60)
{
    // gui.exe:0x1400B61A0
    auto item = QSharedPointer<urlItem>::create(url.toString(), 1, QByteArray());
    item->field60 = field60;
    item->field94 = true;
    item->field6C = depth;
    return item;
}
