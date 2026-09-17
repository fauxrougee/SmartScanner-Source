#include "httpissuecapture.h"

#include "httpclient.h"

namespace {

constexpr auto payloadAttribute = static_cast<QNetworkRequest::Attribute>(1003);
constexpr auto cookieAttribute = static_cast<QNetworkRequest::Attribute>(1006);

} // namespace

QByteArray nativeIssueRequestCapture(const QNetworkRequest &request)
{
    // gui.exe:0x14013C520.  The verb has no fallback: it is attribute 10
    // (CustomVerbAttribute) even when the QByteArray is empty.
    const QByteArray method = request.attribute(QNetworkRequest::CustomVerbAttribute).toByteArray();
    const QByteArray payload = request.attribute(payloadAttribute).toByteArray();
    const QByteArray cookies = request.attribute(cookieAttribute).toByteArray();
    QByteArray path = request.url().toString(
        static_cast<QUrl::ComponentFormattingOptions>(32506015)).toUtf8();
    if (path.isEmpty())
        path = QByteArrayLiteral("/");

    QByteArray result = method + QByteArrayLiteral(" ") + path
        + QByteArrayLiteral(" HTTP/1.1\r\n");
    for (const QByteArray &name : request.rawHeaderList()) {
        // The native skips all cookie headers only when its separate cookie
        // attribute is non-empty, then emits the one synthetic lower-case line.
        if (!cookies.isEmpty() && name.toLower() == QByteArrayLiteral("cookie"))
            continue;
        result += name;
        result += QByteArrayLiteral(": ");
        result += request.rawHeader(name);
        result += QByteArrayLiteral("\r\n");
    }
    if (!cookies.isEmpty())
        result += QByteArrayLiteral("cookie: ") + cookies + QByteArrayLiteral("\r\n");

    if (!payload.isEmpty()
        && !result.toLower().contains(QByteArrayLiteral("\r\ncontent-length: "))) {
        result += QByteArrayLiteral("content-length: ")
            + QByteArray::number(payload.size()) + QByteArrayLiteral("\r\n");
    }
    result += QByteArrayLiteral("\r\n");
    if (!payload.isEmpty())
        result += payload;
    return result;
}

QByteArray nativeIssueResponseCapture(const HttpResponse &response)
{
    // gui.exe:0x140134350 calls 0x140134390 with the native body offset and a
    // maximum of 500.  Its final <=19-byte allowance preserves a short tail.
    const qsizetype bodyOffset = qBound<qsizetype>(0, response.bodyOffset, response.raw.size());
    const qsizetype bodyLength = response.raw.size() - bodyOffset;
    constexpr qsizetype limit = 500;
    qsizetype capturedLength = qMin(bodyLength, limit);
    if (bodyLength - capturedLength <= 19)
        capturedLength = bodyLength;

    QByteArray result = response.raw.left(bodyOffset);
    result += response.raw.mid(bodyOffset, capturedLength);
    if (capturedLength < bodyLength)
        result += QByteArrayLiteral("\r\n...[truncated]...");
    return result;
}
