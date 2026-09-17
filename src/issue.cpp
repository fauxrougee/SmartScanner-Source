#include "issue.h"
#include "urlnormalizer.h"

#include <QJsonArray>
#include <QJsonValue>

static_assert(sizeof(Issue) == 632,
              "Recovered Issue layout must match gui.exe:0x1400217F0");

Issue::Issue(const Issue &other)
    : field00(other.field00)
    , field18(other.field18)
    , field30(other.field30)
    , field38(other.field38)
    , field40(other.field40)
    , field58(other.field58)
    , field70(other.field70)
    , field88(other.field88)
    , fieldA0(other.fieldA0)
    , fieldA8(other.fieldA8)
    , fieldC0(other.fieldC0)
    , fieldD8(other.fieldD8)
    , fieldF0(other.fieldF0)
    , field108(other.field108)
    , field110(other.field110)
    , field118(other.field118)
    , field130(other.field130)
    , field148(other.field148)
    , field160(other.field160)
    , field178(other.field178)
    , field190(other.field190)
    , field1A8(other.field1A8)
    , field1C0(other.field1C0)
    , field1D8(other.field1D8)
    , field1F0(other.field1F0)
    , field208(other.field208)
    , field220(other.field220)
    , field250(other.field250)
    , field258(other.field258)
    , field260(other.field260)
{
    // gui.exe:0x1400217F0 initializes field238 independently.
}

Issue::Issue(Issue &&other)
    : Issue(static_cast<const Issue &>(other))
{
}

Issue &Issue::operator=(const Issue &other)
{
    if (this == &other)
        return *this;

    field00 = other.field00;
    field18 = other.field18;
    field30 = other.field30;
    field38 = other.field38;
    field40 = other.field40;
    field58 = other.field58;
    field70 = other.field70;
    field88 = other.field88;
    fieldA0 = other.fieldA0;
    fieldA8 = other.fieldA8;
    fieldC0 = other.fieldC0;
    fieldD8 = other.fieldD8;
    fieldF0 = other.fieldF0;
    field108 = other.field108;
    field110 = other.field110;
    field118 = other.field118;
    field130 = other.field130;
    field148 = other.field148;
    field160 = other.field160;
    field178 = other.field178;
    field190 = other.field190;
    field1A8 = other.field1A8;
    field1C0 = other.field1C0;
    field1D8 = other.field1D8;
    field1F0 = other.field1F0;
    field208 = other.field208;
    field220 = other.field220;
    field250 = other.field250;
    field258 = other.field258;
    field260 = other.field260;
    return *this;
}

Issue &Issue::operator=(Issue &&other)
{
    return operator=(static_cast<const Issue &>(other));
}

quint64 Issue::identity()
{
    field238.lock();
    if (!field18.isEmpty() && field250 == 0) {
        const QString source = field18 + UrlNormalizer::canonicalForIssue(field30)
                               + field70 + QString::number(fieldA0);
        field250 = qHash(QStringView(source), 0);
    }
    const quint64 result = field250;
    field238.unlock();
    return result;
}

// sms.exe:0x1400228D0 - Converts Issue to JSON for report output
QJsonObject Issue::toJsonObject() const
{
    QJsonObject obj;

    // Always include id (identity hash)
    obj.insert(QStringLiteral("id"), static_cast<qint64>(const_cast<Issue*>(this)->identity()));

    // dbId - only if not null
    if (!field00.isNull())
        obj.insert(QStringLiteral("dbId"), field00);

    // Required fields
    obj.insert(QStringLiteral("name"), field18);
    obj.insert(QStringLiteral("url"), field30.toString());
    obj.insert(QStringLiteral("impact"), field38);
    obj.insert(QStringLiteral("restriction"), field110);

    // Optional string fields - only if not empty
    if (!field58.isEmpty())
        obj.insert(QStringLiteral("details"), field58);
    if (!fieldA8.isEmpty())
        obj.insert(QStringLiteral("recommendation"), fieldA8);
    if (!field40.isEmpty())
        obj.insert(QStringLiteral("referer"), field40);
    if (!fieldC0.isEmpty())
        obj.insert(QStringLiteral("description"), fieldC0);

    // customFields - QHash<QString, QSet<QString>> as array of {key, values}
    if (!field108.isEmpty()) {
        QJsonArray customFieldsArray;
        for (auto it = field108.cbegin(); it != field108.cend(); ++it) {
            QJsonObject fieldObj;
            fieldObj.insert(QStringLiteral("key"), it.key());
            QJsonArray valuesArray;
            for (const QString &value : it.value())
                valuesArray.append(value);
            fieldObj.insert(QStringLiteral("values"), valuesArray);
            customFieldsArray.append(fieldObj);
        }
        obj.insert(QStringLiteral("customFields"), customFieldsArray);
    }

    // parameter object - only if fieldA0 != 0
    if (fieldA0 != 0) {
        QJsonObject paramObj;
        paramObj.insert(QStringLiteral("name"), field70);
        paramObj.insert(QStringLiteral("value"), field88);
        obj.insert(QStringLiteral("parameter"), paramObj);
    }

    // Request/response headers (fieldD8 and fieldF0)
    if (!fieldD8.isEmpty()) {
        QJsonArray headersArray;
        for (const auto &pair : fieldD8) {
            QJsonObject headerObj;
            headerObj.insert(QStringLiteral("name"), pair.first);
            headerObj.insert(QStringLiteral("value"), pair.second);
            headersArray.append(headerObj);
        }
        obj.insert(QStringLiteral("headers"), headersArray);
    }

    return obj;
}

namespace {

// Exact Qt 6.8 QSizeType encoding used by the binary's calls to the private
// QDataStream helpers. Kept locally because those helpers are private API.
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
    } else if (stream.version() >= QDataStream::Qt_6_7) {
        stream << kExtendedSize << size;
    } else if (size == qint64(kExtendedSize)) {
        stream << kExtendedSize;
    } else {
        stream.setStatus(QDataStream::SizeLimitExceeded);
        return false;
    }
    return true;
}

template <typename T>
bool writeList(QDataStream &stream, const QList<T> &values)
{
    if (!writeSize(stream, values.size()))
        return false;
    for (const T &value : values)
        stream << value;
    return stream.status() == QDataStream::Ok;
}

template <typename T>
bool readList(QDataStream &stream, QList<T> *values)
{
    const qint64 size = readSize(stream);
    if (size < 0) {
        stream.setStatus(QDataStream::ReadCorruptData);
        return false;
    }

    values->clear();
    values->reserve(qsizetype(size));
    for (qint64 index = 0; index < size; ++index) {
        T value;
        stream >> value;
        if (stream.status() != QDataStream::Ok)
            return false;
        values->append(std::move(value));
    }
    return true;
}

bool writeCustomFields(QDataStream &stream,
                       const QHash<QString, QSet<QString>> &values)
{
    if (!writeSize(stream, values.size()))
        return false;
    for (auto it = values.cbegin(); it != values.cend(); ++it) {
        stream << it.key();
        if (!writeSize(stream, it.value().size()))
            return false;
        for (const QString &value : it.value())
            stream << value;
    }
    return stream.status() == QDataStream::Ok;
}

bool readCustomFields(QDataStream &stream, QHash<QString, QSet<QString>> *values)
{
    const qint64 size = readSize(stream);
    if (size < 0) {
        stream.setStatus(QDataStream::ReadCorruptData);
        return false;
    }

    values->clear();
    for (qint64 index = 0; index < size; ++index) {
        QString key;
        stream >> key;
        const qint64 valueCount = readSize(stream);
        if (valueCount < 0) {
            stream.setStatus(QDataStream::ReadCorruptData);
            return false;
        }

        QSet<QString> entries;
        for (qint64 valueIndex = 0; valueIndex < valueCount; ++valueIndex) {
            QString value;
            stream >> value;
            if (stream.status() != QDataStream::Ok)
                return false;
            entries.insert(std::move(value));
        }
        values->insert(std::move(key), std::move(entries));
    }
    return true;
}

} // namespace

QDataStream &operator<<(QDataStream &stream, const Issue &issue)
{
    // Exact order from gui.exe:0x140023140.
    stream << issue.field250;
    stream << issue.field00 << issue.field18 << issue.field30 << issue.field38;
    stream << issue.field40 << issue.field58 << issue.field70 << issue.field88;
    stream << issue.fieldA0 << issue.fieldA8 << issue.fieldC0;
    if (!writeList(stream, issue.fieldD8) || !writeList(stream, issue.fieldF0)
        || !writeCustomFields(stream, issue.field108))
        return stream;
    stream << issue.field110;
    writeList(stream, issue.field118);
    writeList(stream, issue.field130);
    writeList(stream, issue.field148);
    writeList(stream, issue.field160);
    writeList(stream, issue.field178);
    writeList(stream, issue.field190);
    writeList(stream, issue.field1A8);
    writeList(stream, issue.field1C0);
    writeList(stream, issue.field1D8);
    writeList(stream, issue.field1F0);
    writeList(stream, issue.field208);
    writeList(stream, issue.field220);
    return stream;
}

QDataStream &operator>>(QDataStream &stream, Issue &issue)
{
    // Direct inverse of gui.exe:0x1400DD100.
    stream >> issue.field250;
    stream >> issue.field00 >> issue.field18 >> issue.field30 >> issue.field38;
    stream >> issue.field40 >> issue.field58 >> issue.field70 >> issue.field88;
    stream >> issue.fieldA0 >> issue.fieldA8 >> issue.fieldC0;
    if (stream.status() != QDataStream::Ok || !readList(stream, &issue.fieldD8)
        || !readList(stream, &issue.fieldF0)
        || !readCustomFields(stream, &issue.field108))
        return stream;
    stream >> issue.field110;
    if (stream.status() != QDataStream::Ok)
        return stream;
    readList(stream, &issue.field118);
    readList(stream, &issue.field130);
    readList(stream, &issue.field148);
    readList(stream, &issue.field160);
    readList(stream, &issue.field178);
    readList(stream, &issue.field190);
    readList(stream, &issue.field1A8);
    readList(stream, &issue.field1C0);
    readList(stream, &issue.field1D8);
    readList(stream, &issue.field1F0);
    readList(stream, &issue.field208);
    readList(stream, &issue.field220);
    return stream;
}
