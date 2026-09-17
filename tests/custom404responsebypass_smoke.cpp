#include "custom404responsebypass.h"

#include "httpclient.h"

#include <QCoreApplication>

namespace {

void addHeader(HttpResponse &response, const QByteArray &name, const QByteArray &value)
{
    const qsizetype nameOffset = response.raw.size();
    response.raw += name;
    const qsizetype valueOffset = response.raw.size();
    response.raw += value;
    HttpResponse::HeaderRange range;
    range.name = {nameOffset, name.size()};
    range.value = {valueOffset, value.size()};
    response.field120.append(range);
}

HttpResponse responseWithBody(const QByteArray &body)
{
    HttpResponse response;
    response.raw = body;
    response.bodyLength = body.size();
    return response;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    HttpResponse nonHtml = responseWithBody(QByteArrayLiteral("plain"));
    nonHtml.statusCode = 200;
    addHeader(nonHtml, QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/plain"));
    if (!custom404ResponseBypassesErrorEvidence(nonHtml))
        return 1;

    HttpResponse ordinaryHtml = responseWithBody(QByteArrayLiteral("<html>ordinary</html>"));
    ordinaryHtml.statusCode = 200;
    addHeader(ordinaryHtml, QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/html"));
    if (custom404ResponseBypassesErrorEvidence(ordinaryHtml))
        return 2;

    HttpResponse cached = responseWithBody(QByteArrayLiteral("<html>ordinary</html>"));
    addHeader(cached, QByteArrayLiteral("X-Mod-Pagespeed"), QByteArray());
    if (!custom404ResponseBypassesErrorEvidence(cached))
        return 3;

    HttpResponse paragraph = responseWithBody(
        QByteArrayLiteral("<p>") + QByteArray(600, 'x') + QByteArrayLiteral("</p>"));
    if (!custom404ResponseBypassesErrorEvidence(paragraph))
        return 4;
    return 0;
}
