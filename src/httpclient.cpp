#include "httpclient.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QSslError>
#include <QSslSocket>

namespace {

bool usesTls(const QUrl &url)
{
    // sms.exe:0x140148D80: lower-case scheme ending with U+0073, not an
    // equality check against "https".
    return url.scheme().toLower().endsWith(QChar(u's'), Qt::CaseInsensitive);
}

quint16 portForUrl(const QUrl &url)
{
    // sms.exe:0x140149540.
    return static_cast<quint16>(url.port(usesTls(url) ? 443 : 80));
}

QByteArray requestMethod(qint32 value)
{
    // sms.exe:0x140037010. The native literal for value 1 is exactly "G".
    switch (value) {
    case 1: return QByteArrayLiteral("G");
    case 2: return QByteArrayLiteral("POST");
    case 3: return QByteArrayLiteral("PUT");
    case 4: return QByteArrayLiteral("DELETE");
    case 5: return QByteArrayLiteral("PATCH");
    case 6: return QByteArrayLiteral("HEAD");
    default: return {};
    }
}

QByteArray derivedRequestTarget(const QUrl &url)
{
    // sms.exe:0x140149420: FullyEncoded + remove scheme/authority/fragment,
    // followed by QString::trimmed and a null-string-only fallback to '/'.
    QString target = url.toString(QUrl::RemoveScheme | QUrl::RemoveAuthority
                                  | QUrl::RemoveFragment | QUrl::FullyEncoded)
                         .trimmed();
    if (target.isNull())
        target = QStringLiteral("/");
    return target.toUtf8();
}

} // namespace

HttpResponseParser::HttpResponseParser(HttpResponse &response, qint64 startedAtMilliseconds)
    : m_response(response), m_startedAtMilliseconds(startedAtMilliseconds)
{
}

bool HttpResponseParser::feed(const QByteArray &bytes)
{
    m_response.raw.append(bytes);
    return parse();
}

bool HttpResponseParser::isComplete() const noexcept
{
    return m_state == Complete;
}

bool HttpResponseParser::parseHeader(qsizetype lineEnd)
{
    // sms.exe:0x140156740. A colon beyond the CRLF, or no colon, is invalid.
    const qsizetype colon = m_response.raw.indexOf(':', m_cursor);
    if (colon < 0 || colon > lineEnd) {
        m_response.error = HttpResponse::InvalidHeader;
        m_state = Invalid;
        return false;
    }

    qsizetype valueOffset = colon + 1;
    while (valueOffset < lineEnd && m_response.raw.at(valueOffset) == ' ')
        ++valueOffset;

    const QByteArray name = m_response.raw.mid(m_cursor, colon - m_cursor);
    const QByteArray value = m_response.raw.mid(valueOffset, lineEnd - valueOffset);
    m_response.headerRanges.append({m_cursor, lineEnd - m_cursor});

    if (name.compare(QByteArrayLiteral("Content-Length"), Qt::CaseInsensitive) == 0) {
        m_response.bodyMode = HttpResponse::ContentLength;
        m_contentLength = value.toLongLong(nullptr, 10);
    } else if (name.compare(QByteArrayLiteral("Transfer-Encoding"), Qt::CaseInsensitive) == 0
               && value.contains("chunked")) {
        m_response.bodyMode = HttpResponse::Chunked;
    } else if (name.compare(QByteArrayLiteral("Connection"), Qt::CaseInsensitive) == 0
               && value.compare(QByteArrayLiteral("close"), Qt::CaseInsensitive) == 0) {
        m_response.bodyMode = HttpResponse::ConnectionClose;
    }
    return true;
}

bool HttpResponseParser::consumeChunk()
{
    // sms.exe:0x140156560 only records the raw range and skips the following
    // CRLF. It does not validate or decode the payload here.
    if (m_response.raw.size() - m_cursor < m_chunkLength + 2)
        return false;
    m_response.chunkRanges.append({m_cursor, static_cast<qsizetype>(m_chunkLength)});
    m_cursor += m_chunkLength + 2;
    m_state = ChunkLength;
    return true;
}

bool HttpResponseParser::parse()
{
    while (true) {
        switch (m_state) {
        case StatusLine: {
            const qsizetype lineEnd = m_response.raw.indexOf("\r\n", m_cursor);
            if (lineEnd < 0)
                return false;
            m_response.durationMilliseconds = QDateTime::currentMSecsSinceEpoch()
                                              - m_startedAtMilliseconds;
            if (lineEnd < 14) {
                m_response.error = HttpResponse::InvalidStatusLine;
                m_state = Invalid;
                return false;
            }
            bool valid = false;
            m_response.statusCode = m_response.raw.mid(m_cursor + 9, 3).toInt(&valid, 10);
            if (!valid) {
                m_response.error = HttpResponse::InvalidStatusLine;
                m_state = Invalid;
                return false;
            }
            m_response.statusTextOffset = m_cursor + 13;
            m_response.statusTextLength = lineEnd - m_response.statusTextOffset;
            m_cursor = lineEnd + 2;
            m_state = Headers;
            break;
        }
        case Headers: {
            const qsizetype lineEnd = m_response.raw.indexOf("\r\n", m_cursor);
            if (lineEnd < 0)
                return false;
            if (lineEnd != m_cursor) {
                if (!parseHeader(lineEnd))
                    return false;
                m_cursor = lineEnd + 2;
                break;
            }
            m_cursor = lineEnd + 2;
            m_response.bodyOffset = m_cursor;
            if (m_response.bodyMode == HttpResponse::Chunked) {
                m_state = ChunkLength;
            } else {
                if (m_response.bodyMode == HttpResponse::Unspecified)
                    m_response.bodyMode = HttpResponse::ConnectionClose;
                m_state = FixedLengthBody;
            }
            break;
        }
        case FixedLengthBody:
            if (m_response.bodyMode != HttpResponse::ContentLength)
                return false;
            if (m_response.raw.size() - m_cursor < m_contentLength) {
                m_response.bodyLength = m_response.raw.size() - m_cursor;
                return false;
            }
            m_response.bodyLength = m_contentLength;
            m_state = Complete;
            break;
        case ChunkLength: {
            const qsizetype lineEnd = m_response.raw.indexOf("\r\n", m_cursor);
            if (lineEnd < 0)
                return false;
            m_chunkLength = m_response.raw.mid(m_cursor, lineEnd - m_cursor).toLongLong(nullptr, 16);
            m_cursor = lineEnd + 2;
            if (m_chunkLength == 0) {
                m_state = Complete;
                return true;
            }
            m_state = ChunkData;
            break;
        }
        case ChunkData:
            if (!consumeChunk())
                return false;
            break;
        case Complete:
            return true;
        case Invalid:
            return false;
        }
    }
}

HttpClient::HttpClient(QObject *parent) : QObject(parent)
{
    // sms.exe:0x1401561A0 assigns the sole integer member to 90000.
}

QByteArray HttpClient::serializeRequest(const HttpRequestRawPacket &packet)
{
    // sms.exe:0x140159340.
    const QUrl url = packet.url();
    const QByteArray target = packet.payload.isNull() ? derivedRequestTarget(url) : packet.payload;
    QByteArray result;
    result.append(requestMethod(packet.field20));
    result.append(' ');
    result.append(target);
    result.append(' ');
    result.append(packet.protocol);
    result.append("\r\n");

    bool hasHost = false;
    bool hasContentLength = false;
    for (auto it = packet.headers.cbegin(); it != packet.headers.cend(); ++it) {
        for (const HttpRequestItem::HeaderValue &header : it.value()) {
            hasHost = hasHost || header.first.compare(QByteArrayLiteral("host"), Qt::CaseInsensitive) == 0;
            hasContentLength = hasContentLength
                               || header.first.compare(QByteArrayLiteral("content-length"),
                                                       Qt::CaseInsensitive) == 0;
            result.append(header.first);
            result.append(": ");
            result.append(header.second);
            result.append("\r\n");
        }
    }
    if (!hasHost) {
        result.append("Host: ");
        result.append(url.authority(QUrl::PrettyDecoded).toUtf8());
        result.append("\r\n");
    }
    if (!hasContentLength && !packet.field28.isEmpty()) {
        result.append("Content-Length: ");
        result.append(QByteArray::number(packet.field28.size()));
        result.append("\r\n");
    }
    result.append("\r\n");
    result.append(packet.field28);
    return result;
}

HttpResponse HttpClient::perform(const HttpRequestRawPacket &packet) const
{
    // sms.exe:0x140156990. The original accepts the QSslSocket's reported
    // error list; this behaviour is reproduced by the direct signal handler.
    HttpResponse response;
    const QUrl url = packet.url();
    QSslSocket socket;
    if (usesTls(url)) {
        QObject::connect(&socket, &QSslSocket::sslErrors, &socket,
                         [&socket](const QList<QSslError> &errors) {
                             socket.ignoreSslErrors(errors); // 0x140156210
                         });
        socket.connectToHostEncrypted(url.host(), portForUrl(url));
    } else {
        socket.connectToHost(url.host(), portForUrl(url));
    }

    if (!socket.waitForConnected(30000)) {
        response.error = HttpResponse::ConnectionError;
        response.socketError = static_cast<qint32>(socket.error());
        return response;
    }

    socket.write(serializeRequest(packet));
    QElapsedTimer timer;
    timer.start();
    HttpResponseParser parser(response, QDateTime::currentMSecsSinceEpoch());
    bool timedOut = false;
    while (socket.state() == QAbstractSocket::ConnectedState) {
        timedOut = timer.elapsed() >= m_timeoutMilliseconds;
        if (timedOut)
            break;
        socket.waitForReadyRead(30000);
        if (parser.feed(socket.readAll()))
            break;
    }
    socket.abort();
    socket.close();
    if (timedOut) {
        response.error = HttpResponse::Timeout;
        response.socketError = 0;
    }
    return response;
}
