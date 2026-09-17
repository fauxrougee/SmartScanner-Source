#include "custom404errorevidence.h"

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
    response.bodyOffset = 0;
    response.bodyLength = body.size();
    return response;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    HttpResponse plain = responseWithBody(QByteArrayLiteral("not an HTML response"));
    addHeader(plain, QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/plain"));
    if (custom404HasErrorEvidence(plain))
        return 1;

    HttpResponse marker = responseWithBody(QByteArrayLiteral("<html>Page Not Found</html>"));
    addHeader(marker, QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/html"));
    if (!custom404HasErrorEvidence(marker))
        return 2;

    HttpResponse scriptOnly = responseWithBody(
        QByteArrayLiteral("<html><script>Page Not Found</script>normal page</html>"));
    addHeader(scriptOnly, QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/html"));
    // The native regex ends with an empty alternative (`|`), so once the
    // body passes the HTML gate this remains positive even after script text
    // has been removed.
    if (!custom404HasErrorEvidence(scriptOnly))
        return 3;

    HttpResponse headerMarker = responseWithBody(QByteArrayLiteral("<html>ordinary</html>"));
    addHeader(headerMarker, QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/html"));
    addHeader(headerMarker, QByteArrayLiteral("X-Amz-Error-Code"), QByteArray());
    if (!custom404HasErrorEvidence(headerMarker))
        return 4;
    return 0;
}
