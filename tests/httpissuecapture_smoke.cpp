#include "httpclient.h"
#include "httpissuecapture.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    QNetworkRequest request(QUrl(QStringLiteral("http://example.test/path?q=1#fragment")));
    request.setAttribute(QNetworkRequest::CustomVerbAttribute, QByteArrayLiteral("POST"));
    request.setAttribute(static_cast<QNetworkRequest::Attribute>(1003), QByteArrayLiteral("abc"));
    request.setAttribute(static_cast<QNetworkRequest::Attribute>(1006), QByteArrayLiteral("jar=2"));
    request.setRawHeader(QByteArrayLiteral("Cookie"), QByteArrayLiteral("caller=1"));
    request.setRawHeader(QByteArrayLiteral("X-Test"), QByteArrayLiteral("yes"));
    const QByteArray expectedRequest = QByteArrayLiteral(
        "POST /path?q=1 HTTP/1.1\r\nx-test: yes\r\ncookie: jar=2\r\n"
        "content-length: 3\r\n\r\nabc");
    const QByteArray capturedRequest = nativeIssueRequestCapture(request);
    if (capturedRequest != expectedRequest)
        return 1;

    HttpResponse response;
    response.raw = QByteArrayLiteral("HTTP/1.1 200 OK\r\n\r\n") + QByteArray(520, 'a');
    response.bodyOffset = QByteArrayLiteral("HTTP/1.1 200 OK\r\n\r\n").size();
    response.bodyLength = 520;
    const QByteArray expectedResponse = QByteArrayLiteral("HTTP/1.1 200 OK\r\n\r\n")
        + QByteArray(500, 'a') + QByteArrayLiteral("\r\n...[truncated]...");
    if (nativeIssueResponseCapture(response) != expectedResponse)
        return 2;

    response.raw = QByteArrayLiteral("HTTP/1.1 200 OK\r\n\r\n") + QByteArray(519, 'b');
    response.bodyLength = 519;
    if (nativeIssueResponseCapture(response) != response.raw)
        return 3;

    return 0;
}
