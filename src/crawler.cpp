#include "crawler.h"

#include <QNetworkRequest>

namespace {

QByteArray methodForItem(const HttpRequestItem &item)
{
    // gui.exe:0x14001D1B0.
    switch (item.field20) {
    case 1: return QByteArrayLiteral("GET");
    case 2: return QByteArrayLiteral("POST");
    case 3: return QByteArrayLiteral("PUT");
    case 4: return QByteArrayLiteral("DELETE");
    case 5: return QByteArrayLiteral("PATCH");
    case 6: return QByteArrayLiteral("HEAD");
    default: return {};
    }
}

} // namespace

Crawler::Crawler(FileList *fileList, NetworkManager *networkManager,
                 QObject *parent)
    : QObject(parent), m_fileList(fileList), m_networkManager(networkManager)
{
    // gui.exe:0x14010F4D0 copies shared FileList/NetworkManager ownership and
    // initializes the four following qwords to zero.  Scanner owns both
    // objects in this build, so raw non-owning pointers preserve that graph.
}

void Crawler::start()
{
    // gui.exe:0x14010F6B0.
    if (!m_fileList || !m_networkManager)
        return;

    const qint32 available = m_networkManager->concurrentLimit()
                             - static_cast<qint32>(m_networkManager->activeRequests());
    if (available <= 0)
        return;

    const QList<RequestItemPointer> items = m_fileList->itemsFrom(
        static_cast<qsizetype>(m_scheduled), available);
    for (const RequestItemPointer &baseItem : items) {
        // FileList accepts urlItem only (including HtmlForm), matching the
        // unchecked layout accesses in the native loop.
        const QSharedPointer<urlItem> item = qSharedPointerCast<urlItem>(baseItem);
        ++m_scheduled;
        if (item->field94) {
            ++m_crawled;
            continue;
        }

        QNetworkRequest request;
        request.setAttribute(static_cast<QNetworkRequest::Attribute>(1004), item->field6C);
        request.setAttribute(static_cast<QNetworkRequest::Attribute>(1005), item->field58);
        for (auto it = item->headers.cbegin(); it != item->headers.cend(); ++it) {
            for (const HttpRequestItem::HeaderValue &header : it.value())
                request.setRawHeader(header.first, header.second);
        }
        // gui.exe:0x14010F874 supplies the scheduler's shared rules BEFORE
        // the item's url()/body materialization.
        item->setExtensionFrom(&m_valueRules);
        request.setUrl(item->url());
        request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, 2);

        // Native calculation at 0x14010F8CC.  The names are deliberately raw:
        // these values become NetworkManager request attributes 1011 and 1012.
        qint32 field1011 = item->field68;
        if (field1011 == 0) {
            const bool condition = item->field60 == 1 || item->field6C == 0;
            field1011 = (item->field8C == 3 || condition) ? 2553 : 505;
        }
        const QFuture<NetworkManager::ResponsePointer> future = m_networkManager->submit(
            request, methodForItem(*item), item->field28Copy(), field1011,
            item->field60, 0, 0);
        if (!future.isCanceled()) {
            item->field94 = true;
            ++m_crawled;
        }
    }
}
