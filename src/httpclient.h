#pragma once

#include "httprequestrawpacket.h"

#include <QByteArray>
#include <QList>
#include <QNetworkRequest>
#include <QObject>
#include <QPair>
#include <QUrl>

// Clean-room reconstruction of the HttpResponse object allocated by
// sms.exe:0x14012C720. The source-level member names were stripped, so the
// public names below describe only values directly established by the parser.
class HttpResponse final {
public:
    enum Error : quint8 {
        NoError = 0,
        ConnectionError = 1,
        InvalidStatusLine = 2,
        InvalidHeader = 3,
        Timeout = 5,
    };

    enum BodyMode : quint8 {
        Unspecified = 0,
        ContentLength = 1,
        Chunked = 2,
        ConnectionClose = 3,
    };

    struct Range {
        qsizetype offset = 0;
        qsizetype length = 0;
    };

    // gui.exe:0x140133CC0 writes these paired byte ranges into the response
    // container at native offset +0x78.  They are deliberately kept separate
    // from the TCP parser's `headerRanges`, whose producer is sms.exe.
    struct HeaderRange {
        Range name;
        Range value;
    };

    // Native constructor defaults: QNetworkRequest/QUrl default objects,
    // status -1, duration -1, two empty QByteArrays, and zero error state.
    QNetworkRequest request;
    QUrl url;
    qint32 statusCode = -1;
    qsizetype statusTextOffset = 0;
    qsizetype statusTextLength = 0;
    qsizetype bodyOffset = 0;
    qsizetype bodyLength = 0;
    qint64 durationMilliseconds = -1;
    Error error = NoError;
    qint32 socketError = 0;
    QByteArray raw;
    QList<Range> headerRanges;
    QList<Range> chunkRanges;
    BodyMode bodyMode = Unspecified;

    // The GUI reply adapter constructs a second QByteArray and additional
    // zero-initialised state after `raw` (gui.exe:0x140133AD0).  Only the
    // header-pair list below is consumed by the recovered adapter so far;
    // the remaining native state is intentionally not assigned a semantic
    // source name.
    QByteArray field80;
    bool field104 = false;
    QList<HeaderRange> field120;
    bool field168 = false;
    bool field170 = false;
};

// This is the stack-local incremental parser used by
// sms.exe:0x140156250/0x140156560/0x140156740. It deliberately retains ranges
// into HttpResponse::raw instead of decoding chunked content eagerly.
class HttpResponseParser final {
public:
    explicit HttpResponseParser(HttpResponse &response, qint64 startedAtMilliseconds);

    bool feed(const QByteArray &bytes);
    [[nodiscard]] bool isComplete() const noexcept;

private:
    enum State : quint8 {
        StatusLine = 0,
        Headers = 1,
        FixedLengthBody = 2,
        ChunkLength = 3,
        ChunkData = 4,
        Complete = 6,
        Invalid = 7,
    };

    bool parse();
    bool parseHeader(qsizetype lineEnd);
    bool consumeChunk();

    HttpResponse &m_response;
    State m_state = StatusLine;
    qsizetype m_cursor = 0;
    qint64 m_contentLength = 0;
    qint64 m_chunkLength = 0;
    qint64 m_startedAtMilliseconds = 0;
};

// Native class label comes from the direct vtable store at sms.exe:0x1401561A0.
// Its synchronous request routine is sms.exe:0x140156990.
class HttpClient final : public QObject {
    Q_OBJECT
public:
    explicit HttpClient(QObject *parent = nullptr);

    [[nodiscard]] qint32 timeoutMilliseconds() const noexcept { return m_timeoutMilliseconds; }
    void setTimeoutMilliseconds(qint32 timeoutMilliseconds) { m_timeoutMilliseconds = timeoutMilliseconds; }

    // `perform` is a reconstruction label for the native synchronous routine.
    // It opens the URL described by packet; callers must remain within their
    // authorised scan scope.
    [[nodiscard]] HttpResponse perform(const HttpRequestRawPacket &packet) const;

    // sms.exe:0x140159340; useful independently for deterministic inspection.
    [[nodiscard]] static QByteArray serializeRequest(const HttpRequestRawPacket &packet);

private:
    qint32 m_timeoutMilliseconds = 90000;
};
