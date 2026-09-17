#include "requestitemstream.h"

namespace {

constexpr quint32 kNullSize = 0xffffffffu;
constexpr quint32 kExtendedSize = 0xfffffffeu;

qint64 readSize(QDataStream &stream)
{
    quint32 first = 0;
    stream >> first;
    if (first == kNullSize)
        return -1;
    if (first < kExtendedSize || stream.version() < QDataStream::Qt_6_7)
        return qint64(first);

    qint64 extendedSize = 0;
    stream >> extendedSize;
    return extendedSize;
}

bool writeSize(QDataStream &stream, qint64 size)
{
    if (size < qint64(kExtendedSize)) {
        stream << quint32(size);
        return stream.status() == QDataStream::Ok;
    }
    stream << kExtendedSize << size;
    return stream.status() == QDataStream::Ok;
}

} // namespace

QDataStream &writeRequestItem(QDataStream &stream, const RequestItemPointer &item)
{
    // gui.exe:0x140160530 assumes a non-null shared item and dereferences it.
    Q_ASSERT(item);
    stream << item->streamTypeName();
    item->writeToStream(stream);
    return stream;
}

QDataStream &readRequestItem(QDataStream &stream, RequestItemPointer &item)
{
    // gui.exe:0x140160320
    QString typeName;
    stream >> typeName;
    if (stream.status() != QDataStream::Ok)
        return stream;

    if (typeName.compare(QStringLiteral("urlItem"), Qt::CaseInsensitive) == 0)
        item = QSharedPointer<urlItem>::create();
    else if (typeName.compare(QStringLiteral("HtmlForm"), Qt::CaseInsensitive) == 0)
        item = QSharedPointer<HtmlForm>::create();
    else {
        item.clear();
        stream.setStatus(QDataStream::ReadCorruptData);
        return stream;
    }

    item->readFromStream(stream);
    return stream;
}

QDataStream &writeRequestItems(QDataStream &stream, const QList<RequestItemPointer> &items)
{
    // FileList part of gui.exe:0x1400E2910
    if (!writeSize(stream, items.size()))
        return stream;
    for (const RequestItemPointer &item : items)
        writeRequestItem(stream, item);
    return stream;
}

QDataStream &readRequestItems(QDataStream &stream, QList<RequestItemPointer> &items)
{
    // FileList part of gui.exe:0x1400E1CA0 / 0x1400DD3E0
    // The native container reader saves/restores any pre-existing stream
    // error, clears before reading size, and clears partial items on failure.
    const auto previousStatus = stream.status();
    if (!stream.isDeviceTransactionStarted())
        stream.resetStatus();
    struct RestoreStatus {
        QDataStream &stream;
        QDataStream::Status previous;
        ~RestoreStatus() {
            if (previous != QDataStream::Ok) {
                stream.resetStatus();
                stream.setStatus(previous);
            }
        }
    } restore{stream, previousStatus};
    items.clear();
    const qint64 count = readSize(stream);
    if (count < 0) {
        stream.setStatus(QDataStream::SizeLimitExceeded);
        return stream;
    }

    items.reserve(count);
    for (qint64 i = 0; i < count; ++i) {
        RequestItemPointer item;
        readRequestItem(stream, item);
        if (stream.status() != QDataStream::Ok) {
            items.clear();
            return stream;
        }
        items.append(std::move(item));
    }
    return stream;
}
