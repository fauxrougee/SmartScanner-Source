#include "custom404bodycache.h"
#include "custom404classifierstage.h"

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
    response.url = QUrl(QStringLiteral("https://example.test/area/item.php"));
    return response;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    HttpResponse errorPage = responseWithBody(QByteArrayLiteral("<html>ordinary</html>"));
    errorPage.statusCode = 200;
    addHeader(errorPage, QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/html"));
    if (custom404ClassifyNonExceptionalResponse(errorPage, false, {}, {}) != 0)
        return 1;

    HttpResponse redirect = responseWithBody(QByteArrayLiteral("plain"));
    addHeader(redirect, QByteArrayLiteral("location"), QByteArrayLiteral("https://redirect.test/"));
    if (custom404ClassifyNonExceptionalResponse(redirect, false, {}, {}) != 3)
        return 2;

    HttpResponse cached = responseWithBody(QByteArrayLiteral("new candidate"));
    addHeader(cached, QByteArrayLiteral("location"), QByteArrayLiteral("http://[bad"));
    QUrl root(cached.url);
    root.setPath(QStringLiteral("/"), QUrl::DecodedMode);
    QHash<quint64, QByteArray> bodies;
    bodies.insert(custom404DirectoryBodyKey(root), QByteArrayLiteral("root baseline"));
    bodies.insert(custom404DirectoryBodyKey(cached.url), QByteArrayLiteral("directory baseline"));
    if (custom404ClassifyNonExceptionalResponse(cached, false, bodies, {}) != 1)
        return 3;
    return 0;
}
