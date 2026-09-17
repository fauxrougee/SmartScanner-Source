#include "httprequestrawpacket.h"
#include "urlnormalizer.h"

#include <limits>

#include <QUrlQuery>

QUrl HttpRequestItem::url() const {
    return QUrl(target);
}

QDataStream &HttpRequestItem::writeToStream(QDataStream &stream) const {
    // gui.exe:0x1400555C0
    stream << target << field20 << field28;
    qsizetype headerCount = 0;
    for (auto it = headers.cbegin(); it != headers.cend(); ++it)
        headerCount += it.value().size();
    stream << static_cast<quint32>(headerCount);
    for (auto it = headers.cbegin(); it != headers.cend(); ++it) {
        for (const HeaderValue &value : it.value())
            stream << it.key() << value.first << value.second;
    }
    stream << field50;
    return stream;
}

QDataStream &HttpRequestItem::readFromStream(QDataStream &stream) {
    // gui.exe:0x140052B60
    quint32 count = 0;
    stream >> target >> field20 >> field28 >> count;
    if (stream.status() != QDataStream::Ok)
        return stream;
    if (count == std::numeric_limits<quint32>::max()) {
        stream.setStatus(QDataStream::ReadCorruptData);
        return stream;
    }

    headers.clear();
    for (quint32 i = 0; i < count; ++i) {
        QByteArray key;
        QByteArray canonicalName;
        QByteArray value;
        stream >> key >> canonicalName >> value;
        if (stream.status() != QDataStream::Ok)
            return stream;
        headers[key].append(qMakePair(canonicalName, value));
    }
    stream >> field50;
    return stream;
}

QString HttpRequestItem::streamTypeName() const {
    // gui.exe:0x140055170
    return QStringLiteral("HttpRequestItem");
}

QByteArray HttpRequestItem::standardHeaderName(StandardHeader header)
{
    // gui.exe:0x140013240 initializes this int-to-QByteArray map.
    switch (header) {
    case StandardHeader::Referer: return QByteArrayLiteral("Referer");
    case StandardHeader::ContentType: return QByteArrayLiteral("Content-Type");
    case StandardHeader::CacheControl: return QByteArrayLiteral("Cache-Control");
    case StandardHeader::Connection: return QByteArrayLiteral("Connection");
    case StandardHeader::Authorization: return QByteArrayLiteral("Authorization");
    case StandardHeader::Cookie: return QByteArrayLiteral("Cookie");
    case StandardHeader::Host: return QByteArrayLiteral("Host");
    case StandardHeader::UserAgent: return QByteArrayLiteral("User-Agent");
    case StandardHeader::Range: return QByteArrayLiteral("Range");
    case StandardHeader::KeepAlive: return QByteArrayLiteral("Keep-Alive");
    case StandardHeader::WwwAuthenticate: return QByteArrayLiteral("WWW-Authenticate");
    case StandardHeader::Accept: return QByteArrayLiteral("Accept");
    case StandardHeader::AcceptEncoding: return QByteArrayLiteral("Accept-Encoding");
    case StandardHeader::AcceptLanguage: return QByteArrayLiteral("Accept-Language");
    case StandardHeader::Origin: return QByteArrayLiteral("Origin");
    case StandardHeader::ContentLength: return QByteArrayLiteral("Content-Length");
    }
    return {};
}

void HttpRequestItem::setStandardHeader(StandardHeader header, const QByteArray &value)
{
    // gui.exe:0x140071820 gets/creates a header pair by lower-case key, then
    // assigns canonical name and value. The local HeaderMap represents native
    // repeated header storage with a one-element list for this standard path.
    const QByteArray canonicalName = standardHeaderName(header);
    headers[canonicalName.toLower()] = {{canonicalName, value}};
}

QUrl HttpRequestRawPacket::url() const {
    return QUrl(target);
}

QDataStream &HttpRequestRawPacket::writeToStream(QDataStream &stream) const {
    return stream << *this;
}

QDataStream &HttpRequestRawPacket::readFromStream(QDataStream &stream) {
    return stream >> *this;
}

QString HttpRequestRawPacket::streamTypeName() const {
    // gui.exe:0x140089190
    return QStringLiteral("HttpRequestRawPacket");
}

void HttpRequestRawPacket::setHeader(const QByteArray &canonicalName, const QByteArray &value) {
    // gui.exe:0x14003E3B0 stores a lowercase key, canonical name and value;
    // repeated keys retain independent value pairs.
    headers[canonicalName.toLower()].append(qMakePair(canonicalName, value));
}

QDataStream &operator<<(QDataStream &stream, const HttpRequestRawPacket &packet) {
    // sms.exe:0x14007C070. The binary calls QDataStream::writeQSizeType;
    // all ordinary header counts use this same 32-bit representation.
    stream << packet.target << packet.field20 << packet.field28;
    qsizetype headerCount = 0;
    for (auto it = packet.headers.cbegin(); it != packet.headers.cend(); ++it)
        headerCount += it.value().size();
    stream << static_cast<quint32>(headerCount);
    for (auto it = packet.headers.cbegin(); it != packet.headers.cend(); ++it) {
        for (const HttpRequestItem::HeaderValue &value : it.value())
            stream << it.key() << value.first << value.second;
    }
    stream << packet.field50 << packet.payload;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, HttpRequestRawPacket &packet) {
    // sms.exe:0x14007B0C0 and 0x14002E270. The observed reader clears the
    // hash, reads a Qt size, then reads key/first/second for every entry.
    quint32 count = 0;
    stream >> packet.target >> packet.field20 >> packet.field28 >> count;
    if (stream.status() != QDataStream::Ok)
        return stream;

    // A QDataStream container size is never a null marker for this QHash.
    if (count == std::numeric_limits<quint32>::max()) {
        stream.setStatus(QDataStream::ReadCorruptData);
        return stream;
    }

    packet.headers.clear();
    for (quint32 i = 0; i < count; ++i) {
        QByteArray key;
        QByteArray canonicalName;
        QByteArray value;
        stream >> key >> canonicalName >> value;
        if (stream.status() != QDataStream::Ok)
            return stream;
        packet.headers[key].append(qMakePair(canonicalName, value));
    }
    stream >> packet.field50 >> packet.payload;
    return stream;
}

QUrl urlItem::url() const {
    // gui.exe:0x1400553C0
    return QUrl(target);
}

QDataStream &urlItem::writeToStream(QDataStream &stream) const {
    return stream << *this;
}

QDataStream &urlItem::readFromStream(QDataStream &stream) {
    return stream >> *this;
}

QString urlItem::streamTypeName() const {
    // gui.exe:0x140067520
    return QStringLiteral("urlItem");
}

urlItem::urlItem(const QString &targetValue, qint32 requestKind,
                 const QByteArray &field28Value)
    : HttpRequestItem()
{
    // gui.exe:0x140072C20
    target = targetValue;
    field20 = requestKind;
    field28 = field28Value;
}

QByteArray urlItem::field28Copy() const {
    // gui.exe:0x14005F850
    return field28;
}

void urlItem::setExtensionFrom(const void *source) {
    // gui.exe:0x14002B620: no-op base slot.
    Q_UNUSED(source);
}

QDataStream &operator<<(QDataStream &stream, const urlItem &item) {
    // gui.exe:0x140067E60. The original calls a private helper for HeaderMap;
    // its observed wire order is the same key/canonical-name/value order used
    // by HttpRequestRawPacket above.
    stream << item.target << item.field20 << item.field28;
    qsizetype headerCount = 0;
    for (auto it = item.headers.cbegin(); it != item.headers.cend(); ++it)
        headerCount += it.value().size();
    stream << static_cast<quint32>(headerCount);
    for (auto it = item.headers.cbegin(); it != item.headers.cend(); ++it) {
        for (const HttpRequestItem::HeaderValue &value : it.value())
            stream << it.key() << value.first << value.second;
    }
    stream << item.field50 << item.field58 << item.field60 << item.field68
           << item.field70 << item.field88 << item.field8C << item.field90
           << item.field94;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, urlItem &item) {
    // gui.exe:0x1400662D0. The private header-map reader clears then restores
    // every entry in the same order. A null Qt container marker is invalid for
    // this QHash, matching the raw-packet reader's observed treatment.
    quint32 count = 0;
    stream >> item.target >> item.field20 >> item.field28 >> count;
    if (stream.status() != QDataStream::Ok)
        return stream;
    if (count == std::numeric_limits<quint32>::max()) {
        stream.setStatus(QDataStream::ReadCorruptData);
        return stream;
    }

    item.headers.clear();
    for (quint32 i = 0; i < count; ++i) {
        QByteArray key;
        QByteArray canonicalName;
        QByteArray value;
        stream >> key >> canonicalName >> value;
        if (stream.status() != QDataStream::Ok)
            return stream;
        item.headers[key].append(qMakePair(canonicalName, value));
    }

    stream >> item.field50 >> item.field58 >> item.field60 >> item.field68
           >> item.field70 >> item.field88 >> item.field8C >> item.field90
           >> item.field94;
    return stream;
}

QDataStream &operator<<(QDataStream &stream, const HtmlFormInput &input) {
    // gui.exe:0x140067CC0, one 0xa0-byte native input entry.
    stream << input.field00 << input.field18 << input.field30 << input.field48
           << input.field60 << input.field78 << input.field80 << input.field98;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, HtmlFormInput &input) {
    // gui.exe:0x14005B0E0, per-entry read path.
    stream >> input.field00 >> input.field18 >> input.field30 >> input.field48
           >> input.field60 >> input.field78 >> input.field80 >> input.field98;
    return stream;
}

HtmlForm::HtmlForm() {
    // gui.exe:0x14009E530. The numeric request kind is set to 2 and the
    // Content-Type entry is installed through the native header-name table.
    field20 = 2;
    headers[QByteArrayLiteral("content-type")].append(
        qMakePair(QByteArrayLiteral("Content-Type"),
            QByteArrayLiteral("application/x-www-form-urlencoded")));
}

QUrl HtmlForm::url() const {
    // gui.exe:0x140067710
    if (field20 != 1)
        return urlItem::url();

    QUrl result(target);
    const QUrlQuery query(QString::fromUtf8(urlEncoded()));
    if (result.path().isEmpty() && !query.isEmpty())
        result.setPath(QStringLiteral("/"));
    result.setQuery(query);
    return result;
}

QDataStream &HtmlForm::writeToStream(QDataStream &stream) const {
    return stream << *this;
}

QDataStream &HtmlForm::readFromStream(QDataStream &stream) {
    return stream >> *this;
}

QString HtmlForm::streamTypeName() const {
    // gui.exe:0x1400674E0
    return QStringLiteral("HtmlForm");
}

QByteArray HtmlForm::field28Copy() const {
    // gui.exe:0x14005F810
    return field20 == 2 ? urlEncoded() : QByteArray();
}

void HtmlForm::setExtensionFrom(const void *source) {
    // gui.exe:0x140065BB0 tail-calls shared-pointer assignment with destination
    // this+0xb0 and unchanged source argument (0x14001BDA0). Not an output copy.
    fieldB0 = *static_cast<const QSharedPointer<QList<HtmlFormValueRule>> *>(source);
}

QString HtmlForm::valueForInput(const HtmlFormInput &input) const {
    // gui.exe:0x1400679C0: the QString-length gate accepts empty type too.
    if ((input.field30.isEmpty() || input.field30.toLower() == QStringLiteral("text"))
        && !input.field18.isEmpty())
        return input.field18;

    for (const HtmlFormValueRule &rule : *fieldB0) {
        // Match order in 0x140067AF0/7B42/7B95/7BE3.
        if (rule.field08.match(input.field00).hasMatch()
            && rule.field10.match(input.field30).hasMatch()
            && rule.field18.match(input.field80).hasMatch()
            && rule.field00.match(target).hasMatch())
            return rule.field20;
    }
    return QString();
}

QString HtmlForm::defaultValueForInput(const HtmlFormInput &input) const {
    // gui.exe:0x140064F60
    // Raw literals 0x1402C8D50/5C/64: checkbox, radio, select. CaseSensitive=1.
    const bool isCheckBox = input.field30 == QStringLiteral("checkbox");
    const bool isRadio = input.field30 == QStringLiteral("radio");
    if ((isCheckBox || isRadio) && !input.field78)
        return QString();

    if (input.field30 == QStringLiteral("select")
        && input.field18.isEmpty() && !input.field48.isEmpty())
        return input.field48.first();
    return input.field18;
}

QByteArray HtmlForm::urlEncoded() const {
    // gui.exe:0x14005FBF0
    QUrlQuery query;
    for (const HtmlFormInput &input : field98) {
        QString value;
        if (fieldB0)
            value = valueForInput(input);
        if (value.isNull())
            value = defaultValueForInput(input);
        if (!value.isNull())
            query.addQueryItem(input.field00, value);
    }
    return query.toString(QUrl::FullyEncoded).toUtf8();
}

QDataStream &operator<<(QDataStream &stream, const HtmlForm &form) {
    // gui.exe:0x140067CC0
    // fieldB0 is live shared replacement state assigned by the sixth slot;
    // the observed serializer writes only the base item and form inputs.
    stream << static_cast<const urlItem &>(form) << form.field98;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, HtmlForm &form) {
    // gui.exe:0x1400661D0
    stream >> static_cast<urlItem &>(form) >> form.field98;
    return stream;
}

namespace {

quint64 combineHash(quint64 seed, quint64 value)
{
    // The repeated seed/value mix in gui.exe:0x140070D90.
    return seed ^ ((seed >> 2) + value + (seed << 6) + 2654435769ULL);
}

} // namespace

quint64 requestItemIdentity(const HttpRequestItem &item, quint64 seed)
{
    // gui.exe:0x140070D90. Header values are not used by the native identity;
    // it walks the normalised outer header keys and omits the exact lowercase
    // key "referer".
    const QString canonical = UrlNormalizer::canonical(item.url(), static_cast<quint8>(item.field50));
    seed = combineHash(seed, qHash(QStringView(canonical), 0));
    seed = combineHash(seed, qHash(item.field20, 0));
    seed = combineHash(seed, qHash(QByteArrayView(item.field28), 0));

    quint64 headerSeed = 0;
    for (auto it = item.headers.cbegin(); it != item.headers.cend(); ++it) {
        if (it.key() == QByteArrayLiteral("referer"))
            continue;
        headerSeed = combineHash(headerSeed, qHash(QByteArrayView(it.key()), 0));
    }
    return seed ^ (headerSeed + (seed << 6) + (seed >> 2) + 2654435769ULL);
}
