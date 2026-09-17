#include "httpheadercheck.h"
#include "issuedb.h"
#include "urlnormalizer.h"

#include <QCoreApplication>
#include <QNetworkRequest>
#include <QSharedPointer>

namespace {

void addHeader(HttpResponse *response, const QByteArray &name, const QByteArray &value)
{
    HttpResponse::HeaderRange range;
    range.name.offset = response->raw.size();
    range.name.length = name.size();
    response->raw.append(name);
    range.value.offset = response->raw.size();
    range.value.length = value.size();
    response->raw.append(value);
    response->field120.append(range);
}

NetworkManager::ResponsePointer responseWithHeaders(bool addXss, qint32 flags = 8,
                                                     bool safeReferrer = false)
{
    auto response = QSharedPointer<HttpResponse>::create();
    response->url = QUrl(QStringLiteral("https://example.test/page"));
    response->statusCode = 200;
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), flags);
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1012), 1);
    addHeader(response.data(), QByteArrayLiteral("Content-Type"),
              QByteArrayLiteral(" text/html; charset=UTF-8 "));
    if (addXss)
        addHeader(response.data(), QByteArrayLiteral("X-XSS-Protection"),
                  QByteArrayLiteral("1"));
    if (safeReferrer)
        addHeader(response.data(), QByteArrayLiteral("Referrer-Policy"),
                  QByteArrayLiteral("strict-origin"));
    return response;
}

NetworkManager::ResponsePointer textResponseWithBody(const QByteArray &body,
                                                      bool withHpkp = false)
{
    auto response = QSharedPointer<HttpResponse>::create();
    response->url = QUrl(QStringLiteral("http://example.test/plain"));
    response->statusCode = 200;
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 8);
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1012), 1);
    addHeader(response.data(), QByteArrayLiteral("Content-Type"),
              QByteArrayLiteral("text/plain"));
    addHeader(response.data(), QByteArrayLiteral("X-Content-Type-Options"),
              QByteArrayLiteral("nosniff"));
    if (withHpkp) {
        addHeader(response.data(), QByteArrayLiteral("Public-Key-Pins"),
                  QByteArrayLiteral("pin-sha256=\"abc\"; max-age=100"));
    }
    response->bodyOffset = response->raw.size();
    response->raw.append(body);
    response->bodyLength = body.size();
    return response;
}

NetworkManager::ResponsePointer cookieResponse()
{
    auto response = QSharedPointer<HttpResponse>::create();
    response->url = QUrl(QStringLiteral("http://example.test/plain"));
    response->statusCode = 200;
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 8);
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1012), 1);
    addHeader(response.data(), QByteArrayLiteral("Content-Type"),
              QByteArrayLiteral("text/plain"));
    addHeader(response.data(), QByteArrayLiteral("X-Content-Type-Options"),
              QByteArrayLiteral("nosniff"));
    addHeader(response.data(), QByteArrayLiteral("Set-Cookie"),
              QByteArrayLiteral("PHPSESSID=abc; HttpOnly"));
    return response;
}

NetworkManager::ResponsePointer corsResponse()
{
    auto response = QSharedPointer<HttpResponse>::create();
    response->url = QUrl(QStringLiteral("http://example.test/plain"));
    response->statusCode = 200;
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 8);
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1012), 1);
    addHeader(response.data(), QByteArrayLiteral("Content-Type"),
              QByteArrayLiteral("text/plain"));
    addHeader(response.data(), QByteArrayLiteral("X-Content-Type-Options"),
              QByteArrayLiteral("nosniff"));
    addHeader(response.data(), QByteArrayLiteral("Access-Control-Allow-Origin"),
              QByteArrayLiteral(" * "));
    return response;
}

NetworkManager::ResponsePointer owaspResponse()
{
    auto response = QSharedPointer<HttpResponse>::create();
    response->url = QUrl(QStringLiteral("http://example.test/missing"));
    // gui.exe:0x140080500 is outside the `others` response-eligibility gate.
    response->statusCode = 404;
    response->request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 8);
    addHeader(response.data(), QByteArrayLiteral("X-Powered-By"),
              QByteArrayLiteral("PHP/8.3"));
    return response;
}

bool expect(bool value)
{
    return value;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    if (argc != 2)
        return 2;

    IssueDb issues;
    HttpHeaderCheck::process(responseWithHeaders(false), &issues,
                             QStringLiteral("httpheaders@o=owasp,others"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(issues.issues().size() == 5)
        || !expect(issues.issues().at(0).field18
                   == QStringLiteral("X-Frame-Options Header is Missing"))
        || !expect(issues.issues().at(0).field38 == 3)
        || !expect(issues.issues().at(1).field18
                   == QStringLiteral("Strict-Transport-Security Header is Missing"))
        || !expect(issues.issues().at(2).field18
                   == QStringLiteral("Content-Security-Policy Header is Missing"))
        || !expect(issues.issues().at(3).field18
                   == QStringLiteral("X-Content-Type-Options Header is Missing"))
        || !expect(issues.issues().at(3).field38 == 4)
        || !expect(issues.issues().at(4).field18
                   == QStringLiteral("Referrer-Policy Header is Missing"))
        || !expect(issues.issues().at(0).field250
                   == qHash(QStringView(UrlNormalizer::canonical(
                                QUrl(QStringLiteral("https://example.test/page")), 110)
                            + QStringLiteral("@X-Frame-Options@missHeader")), 0))
        || !expect(!issues.issues().at(0).fieldA8.isEmpty()))
        return 1;

    IssueDb xssIssues;
    HttpHeaderCheck::process(responseWithHeaders(true), &xssIssues,
                             QStringLiteral("httpheaders@o=others"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(xssIssues.issues().size() == 6)
        || !expect(xssIssues.issues().at(1).field18
                   == QStringLiteral("X-XSS-Protection Header is Set"))
        || !expect(xssIssues.issues().at(1).field38 == 4))
        return 1;

    IssueDb safeReferrer;
    HttpHeaderCheck::process(responseWithHeaders(false, 8, true), &safeReferrer,
                             QStringLiteral("httpheaders@o=others"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(safeReferrer.issues().size() == 4))
        return 1;

    IssueDb charsetIssues;
    HttpHeaderCheck::process(textResponseWithBody(QByteArrayLiteral("plain text")),
                             &charsetIssues, QStringLiteral("httpheaders@o=others"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(charsetIssues.issues().size() == 1)
        || !expect(charsetIssues.issues().first().field18
                   == QStringLiteral("Content Character Encoding is not Defined"))
        || !expect(charsetIssues.issues().first().field38 == 4))
        return 1;

    IssueDb markedBody;
    HttpHeaderCheck::process(textResponseWithBody(QByteArray::fromHex("EFBBBF6869")),
                             &markedBody, QStringLiteral("httpheaders@o=others"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(markedBody.issues().isEmpty()))
        return 1;

    IssueDb hpkpIssues;
    HttpHeaderCheck::process(textResponseWithBody({}, true), &hpkpIssues,
                             QStringLiteral("httpheaders@o=others"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(hpkpIssues.issues().size() == 1)
        || !expect(hpkpIssues.issues().first().field18
                   == QStringLiteral("Public-Key-Pins Header is Set"))
        || !expect(hpkpIssues.issues().first().field38 == 4)
        || !expect(hpkpIssues.issues().first().field108
                   .value(QStringLiteral("HPKP"))
                   .contains(QStringLiteral("pin-sha256=\"abc\"; max-age=100"))))
        return 1;

    IssueDb cookieIssues;
    HttpHeaderCheck::process(cookieResponse(), &cookieIssues,
                             QStringLiteral("httpheaders@o=others"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(cookieIssues.issues().size() == 2)
        || !expect(cookieIssues.issues().at(0).field18
                   == QStringLiteral("Session Cookie without SameSite Flag"))
        || !expect(cookieIssues.issues().at(0).field38 == 2)
        || !expect(cookieIssues.issues().at(0).field108
                   .value(QStringLiteral("Cookie"))
                   .contains(QStringLiteral("PHPSESSID=abc")))
        || !expect(cookieIssues.issues().at(0).field250 != 0)
        || !expect(cookieIssues.issues().at(0).field258)
        || !expect(cookieIssues.issues().at(1).field18
                   == QStringLiteral("Session Cookie without Secure Flag"))
        || !expect(cookieIssues.issues().at(1).field38 == 2))
        return 1;

    IssueDb corsIssues;
    HttpHeaderCheck::process(corsResponse(), &corsIssues,
                             QStringLiteral("httpheaders@o=others"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(corsIssues.issues().size() == 1)
        || !expect(corsIssues.issues().first().field18
                   == QStringLiteral("Cross-Origin Resource Sharing Allowed"))
        || !expect(corsIssues.issues().first().field38 == 4)
        || !expect(corsIssues.issues().first().field250 != 0)
        || !expect(corsIssues.issues().first().field258))
        return 1;

    IssueDb owaspIssues;
    HttpHeaderCheck::process(owaspResponse(), &owaspIssues,
                             QStringLiteral("httpheaders@o=owasp"),
                             QString::fromLocal8Bit(argv[1]));
    if (!expect(owaspIssues.issues().size() == 1)
        || !expect(owaspIssues.issues().first().field18
                   == QStringLiteral("X-Powered-By Header Found"))
        || !expect(owaspIssues.issues().first().field38 == 4)
        || !expect(owaspIssues.issues().first().field250 != 0)
        || !expect(owaspIssues.issues().first().field258))
        return 1;

    IssueDb ignored;
    HttpHeaderCheck::process(responseWithHeaders(false, 0), &ignored,
                             QStringLiteral("httpheaders@o=others"),
                             QString::fromLocal8Bit(argv[1]));
    return ignored.issues().isEmpty() ? 0 : 1;
}
