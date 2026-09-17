#include "custom404responsebypass.h"

#include "httpclient.h"

#include <QRegularExpression>

namespace {

bool hasHeader(const HttpResponse &response, const QByteArray &wanted)
{
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray name = response.raw.mid(range.name.offset, range.name.length);
        if (name.compare(wanted, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

QByteArray headerValue(const HttpResponse &response, const QByteArray &wanted)
{
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray name = response.raw.mid(range.name.offset, range.name.length);
        if (name.compare(wanted, Qt::CaseInsensitive) == 0)
            return response.raw.mid(range.value.offset, range.value.length);
    }
    return {};
}

QByteArray bodyBytes(const HttpResponse &response)
{
    return response.raw.mid(response.bodyOffset, response.bodyLength);
}

QString compactHtmlText(QString text)
{
    // gui.exe:0x140137F50.
    static const QRegularExpression script(QStringLiteral("<script[\\s\\S]+?</script>"),
                                           QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression tag(QStringLiteral("<[^<>]*>"));
    text.replace(script, QStringLiteral(" "));
    text.replace(tag, QStringLiteral(" "));
    return text.simplified();
}

} // namespace

bool custom404ResponseBypassesErrorEvidence(const HttpResponse &response)
{
    // gui.exe:0x14014C770. In its only recovered caller, the third argument
    // is a default/null QString, reducing the late paragraph condition to the
    // explicit body-only route below.
    if (response.statusCode == 200 && hasHeader(response, QByteArrayLiteral("Content-Type"))
        && !headerValue(response, QByteArrayLiteral("Content-Type"))
                .toLower()
                .startsWith(QByteArrayLiteral("text/html"))) {
        return true;
    }

    static const QList<QByteArray> bypassHeaders{
        QByteArrayLiteral("nginx-cache"), QByteArrayLiteral("x-nginx-cache-status"),
        QByteArrayLiteral("x-mod-pagespeed"), QByteArrayLiteral("wp-super-cache"),
        QByteArrayLiteral("x-acc-exp"), QByteArrayLiteral("x-akamai-transformed"),
        QByteArrayLiteral("x-content-digest")};
    for (const QByteArray &header : bypassHeaders) {
        if (hasHeader(response, header))
            return true;
    }

    const QByteArray body = bodyBytes(response);
    if (body.size() > 50000 || body.contains(QByteArrayLiteral("<form")))
        return true;

    static const QRegularExpression paragraph(
        QStringLiteral("<p(?:>|(?:\\s.*)>)[\\s\\S]+</p>"),
        QRegularExpression::CaseInsensitiveOption);
    const QString captured = paragraph.match(QString::fromUtf8(body)).captured(0);
    return !captured.isNull() && compactHtmlText(captured).size() > 500;
}
