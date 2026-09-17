#pragma once

#include <QByteArray>
#include <QDataStream>
#include <QHash>
#include <QList>
#include <QPair>
#include <QRegularExpression>
#include <QString>
#include <QSharedPointer>
#include <QUrl>

// Clean-room field and stream reconstruction of sms.exe HttpRequestItem and
// HttpRequestRawPacket. Field names marked "field" deliberately retain their
// observed offsets rather than claiming an unrecovered semantic name.
class HttpRequestItem {
public:
    // gui.exe:0x140013240 / 0x140071820. The numeric values are the native
    // table keys used by crawler request producers.
    enum class StandardHeader : qint32 {
        Referer = 1,
        ContentType,
        CacheControl,
        Connection,
        Authorization,
        Cookie,
        Host,
        UserAgent,
        Range,
        KeepAlive,
        WwwAuthenticate,
        Accept,
        AcceptEncoding,
        AcceptLanguage,
        Origin,
        ContentLength,
    };

    // The native vtable starts with these four methods. It has no virtual
    // destructor entry, so the destructor intentionally remains non-virtual.
    ~HttpRequestItem() = default;

    using HeaderValue = QPair<QByteArray, QByteArray>;
    using HeaderValues = QList<HeaderValue>;
    using HeaderMap = QHash<QByteArray, HeaderValues>;

    [[nodiscard]] virtual QUrl url() const;
    virtual QDataStream &writeToStream(QDataStream &stream) const;
    virtual QDataStream &readFromStream(QDataStream &stream);
    [[nodiscard]] virtual QString streamTypeName() const;

    // gui.exe:0x140071820. Replaces the canonical/value pair for the mapped
    // standard header rather than appending a second pair.
    void setStandardHeader(StandardHeader header, const QByteArray &value);
    [[nodiscard]] static QByteArray standardHeaderName(StandardHeader header);

    QString target;
    qint32 field20 = 1;
    QByteArray field28;
    HeaderMap headers;
    qint32 field50 = 15;
};

class HttpRequestRawPacket final : public HttpRequestItem {
public:
    [[nodiscard]] QUrl url() const override;
    QDataStream &writeToStream(QDataStream &stream) const override;
    QDataStream &readFromStream(QDataStream &stream) override;
    [[nodiscard]] QString streamTypeName() const override;

    // Observed at offsets +0x58 and +0x70. The original stream excludes
    // protocol and includes payload.
    QByteArray protocol;
    QByteArray payload;

    void setHeader(const QByteArray &canonicalName, const QByteArray &value);
};

QDataStream &operator<<(QDataStream &stream, const HttpRequestRawPacket &packet);
QDataStream &operator>>(QDataStream &stream, HttpRequestRawPacket &packet);

// `urlItem` is the exact class spelling preserved in gui.exe RTTI. Its
// constructor is gui.exe:0x14005CDA0 and its stream virtuals are
// 0x140067E60 / 0x1400662D0. Fields without an in-class initializer were not
// initialized by the observed constructor, so this source deliberately does
// not assign one either.
class urlItem : public HttpRequestItem {
public:
    urlItem() = default;

    // gui.exe:0x140072C20. Shared by crawler and index producers; it assigns
    // only the inherited target, request-kind and byte-array fields before
    // performing the normal urlItem initialization.
    urlItem(const QString &target, qint32 requestKind, const QByteArray &field28);

    [[nodiscard]] QUrl url() const override;
    QDataStream &writeToStream(QDataStream &stream) const override;
    QDataStream &readFromStream(QDataStream &stream) override;
    [[nodiscard]] QString streamTypeName() const override;

    // This is the fifth `urlItem` virtual (gui.exe:0x14005F850). The member
    // name is a reconstruction label; the binary only proves that it returns
    // a copy of the QByteArray at base offset +0x28.
    [[nodiscard]] virtual QByteArray field28Copy() const;

    // Sixth slot (gui.exe:0x14002B620) is a no-op for urlItem. HtmlForm's
    // override consumes the caller's shared rules. Name is reconstructed.
    virtual void setExtensionFrom(const void *source);

    qint32 field58 = 0;
    qint64 field60 = 0;
    qint32 field68 = 0;
    // Native offset +0x6c. Initialized by the constructor, but not written by
    // urlItem's stream; FileList uses it as request depth.
    qint32 field6C = 0;
    QString field70;
    qint32 field88 = 5;
    qint32 field8C;
    qint32 field90;
    bool field94 = false;
};

// The installed binary's object is 0x98 bytes. Do not assert that size here:
// the Qt `QHash` ABI in the local build toolchain has a different object size,
// while the recovered member order and on-disk stream order remain valid.

QDataStream &operator<<(QDataStream &stream, const urlItem &item);
QDataStream &operator>>(QDataStream &stream, urlItem &item);

// The native HtmlForm input entry occupies 0xa0 bytes in gui.exe. Field names
// are offsets because their source-level names were removed by compilation.
class HtmlFormInput final {
public:
    QString field00;
    QString field18;
    QString field30;
    QList<QString> field48;
    QList<QString> field60;
    bool field78 = false;
    QString field80;
    QHash<QString, QString> field98;
};

QDataStream &operator<<(QDataStream &stream, const HtmlFormInput &input);
QDataStream &operator>>(QDataStream &stream, HtmlFormInput &input);

// A 56-byte native form-value rule: four regular expressions followed by a
// replacement QString. It is held in HtmlForm's field at native offset +0xb0.
class HtmlFormValueRule final {
public:
    QRegularExpression field00;
    QRegularExpression field08;
    QRegularExpression field10;
    QRegularExpression field18;
    QString field20;
};

class HtmlForm final : public urlItem {
public:
    HtmlForm();

    [[nodiscard]] QUrl url() const override;
    QDataStream &writeToStream(QDataStream &stream) const override;
    QDataStream &readFromStream(QDataStream &stream) override;
    [[nodiscard]] QString streamTypeName() const override;
    [[nodiscard]] QByteArray field28Copy() const override;
    void setExtensionFrom(const void *source) override;

    [[nodiscard]] QByteArray urlEncoded() const;

    QList<HtmlFormInput> field98;
    // gui.exe:0x140065BB0 -> 0x14001BDA0 assigns FROM the caller. The
    // constructor zeroes two shared-pointer words, not a QList's three.
    QSharedPointer<QList<HtmlFormValueRule>> fieldB0;

private:
    [[nodiscard]] QString valueForInput(const HtmlFormInput &input) const;
    [[nodiscard]] QString defaultValueForInput(const HtmlFormInput &input) const;
};

QDataStream &operator<<(QDataStream &stream, const HtmlForm &form);
QDataStream &operator>>(QDataStream &stream, HtmlForm &form);

// gui.exe:0x140070D90. Used by FileList before insertion; the optional seed
// is the native function's second parameter.
quint64 requestItemIdentity(const HttpRequestItem &item, quint64 seed = 0);
