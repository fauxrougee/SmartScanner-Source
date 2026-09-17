#include "cachecontrolrule.h"
#include "httpclient.h"

#include <QCoreApplication>
#include <QNetworkRequest>

namespace {

void addHeader(HttpResponse *response, const QByteArray &name, const QByteArray &value)
{
    HttpResponse::HeaderRange range;
    range.name.offset = response->raw.size();
    range.name.length = name.size();
    response->raw += name;
    range.value.offset = response->raw.size();
    range.value.length = value.size();
    response->raw += value;
    response->field120 += range;
}

HttpResponse dynamicHtmlResponse()
{
    HttpResponse response;
    response.url = QUrl(QStringLiteral("https://example.test/index.php"));
    response.statusCode = 200;
    response.request.setAttribute(static_cast<QNetworkRequest::Attribute>(1012), 1);
    addHeader(&response, QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/html"));
    response.bodyOffset = response.raw.size();
    response.bodyLength = 0;
    return response;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    HttpResponse missing = dynamicHtmlResponse();
    const auto missingFinding = evaluateCacheControlRule(missing, 1);
    if (!missingFinding
        || missingFinding->details != QStringLiteral("The `Cache-Control` header is not set")
        || missingFinding->identitySuffix != QStringLiteral("bad-cache-control@")) {
        return 1;
    }

    HttpResponse insecure = dynamicHtmlResponse();
    addHeader(&insecure, QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("public, max-age=10"));
    const auto insecureFinding = evaluateCacheControlRule(insecure, -2);
    if (!insecureFinding
        || insecureFinding->identitySuffix != QStringLiteral("bad-cache-control@public, max-age=10")
        || insecureFinding->details
            != QStringLiteral("The `Cache-Control` header does not have any of (`no-store`,`no-cache`,`private`,`max-age=0, must-revalidate`) directives")) {
        return 2;
    }

    HttpResponse safe = dynamicHtmlResponse();
    addHeader(&safe, QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("private"));
    if (evaluateCacheControlRule(safe, 1))
        return 3;

    HttpResponse meta = dynamicHtmlResponse();
    meta.raw += QByteArrayLiteral("<meta http-equiv=Cache-Control content=no-store>");
    meta.bodyLength = meta.raw.size() - meta.bodyOffset;
    if (evaluateCacheControlRule(meta, 1))
        return 4;

    if (evaluateCacheControlRule(missing, 0))
        return 5;

    HttpResponse trailingDot = dynamicHtmlResponse();
    trailingDot.url = QUrl(QStringLiteral("https://example.test/index."));
    if (!evaluateCacheControlRule(trailingDot, 1))
        return 6;

    return 0;
}
