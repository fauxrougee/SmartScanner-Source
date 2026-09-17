#include "custom404errorevidence.h"

#include "httpclient.h"

#include <QRegularExpression>

namespace {

QByteArray headerValue(const HttpResponse &response, const QByteArray &wanted)
{
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray name = response.raw.mid(range.name.offset, range.name.length);
        if (name.compare(wanted, Qt::CaseInsensitive) == 0)
            return response.raw.mid(range.value.offset, range.value.length);
    }
    return {};
}

bool hasHeader(const HttpResponse &response, const QByteArray &wanted)
{
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray name = response.raw.mid(range.name.offset, range.name.length);
        if (name.compare(wanted, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

QByteArray bodyBytes(const HttpResponse &response)
{
    return response.raw.mid(response.bodyOffset, response.bodyLength);
}

} // namespace

bool custom404HasErrorEvidence(const HttpResponse &response)
{
    // gui.exe:0x14014CE80. The raw body replaces NUL with ASCII space before
    // QString conversion.
    QByteArray body = bodyBytes(response);
    body.replace('\0', ' ');
    QString text = QString::fromUtf8(body);

    static const QRegularExpression htmlTag(
        QStringLiteral("<(html|head|body|div|a|span|script|h[1-6]|p|!DOCTYPE html)"),
        QRegularExpression::CaseInsensitiveOption);
    const QByteArray contentType = headerValue(response, QByteArrayLiteral("Content-Type")).toLower();
    if (!contentType.startsWith(QByteArrayLiteral("text/html")) && !htmlTag.match(text).hasMatch())
        return false;

    static const QRegularExpression script(
        QStringLiteral("<script[\\s\\S]+?</script>"),
        QRegularExpression::CaseInsensitiveOption);
    text.replace(script, QStringLiteral("\n"));
    static const QRegularExpression errorText(
        QStringLiteral("(?:Could\\s?n.t Find (?:What You\\s?.re|the Page You\\s?.re|the Content You\\s?.re) Looking For)|(?:(?:Page|Content|url) (?:Not Available|Does\\s?n.t Exist|Can\\s?n.t Be|is missing|Not Found))|requested url|not[\\s_-]*found|t[\\s_-]*be[\\s_-]*found|"),
        QRegularExpression::CaseInsensitiveOption);
    if (text.contains(errorText))
        return true;

    static const QList<QByteArray> errorHeaders{
        QByteArrayLiteral("public-extension"), QByteArrayLiteral("x-amz-error-code"),
        QByteArrayLiteral("x-amz-error-detail-key"), QByteArrayLiteral("x-amz-error-message"),
        QByteArrayLiteral("x-404-handler-by"), QByteArrayLiteral("x-404-status-by"),
        QByteArrayLiteral("x-404-host"), QByteArrayLiteral("x-show404"),
        QByteArrayLiteral("nginx-cache")};
    for (const QByteArray &header : errorHeaders) {
        if (hasHeader(response, header))
            return true;
    }
    return false;
}
