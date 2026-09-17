#include "passivechecks.h"
#include "issue.h"
#include "issuedb.h"
#include "issuetemplate.h"
#include "urlnormalizer.h"
#include "httpissuecapture.h"

#include <QNetworkRequest>
#include <QRegularExpression>

namespace {

QByteArray headerValue(const HttpResponse &response, const QByteArray &name)
{
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray headerName = response.raw.mid(range.name.offset, range.name.length);
        if (headerName.compare(name, Qt::CaseInsensitive) == 0)
            return response.raw.mid(range.value.offset, range.value.length);
    }
    return {};
}

void setNativeIdentity(Issue *issue, const HttpResponse &response, const QString &suffix)
{
    issue->field250 = qHash(QStringView(UrlNormalizer::canonical(response.url, 110)
                                        + QLatin1Char('@') + suffix), 0);
    issue->field258 = true;
}

void attachNativeHttpCapture(Issue *issue, const HttpResponse &response)
{
    issue->fieldF0.append(qMakePair(nativeIssueRequestCapture(response.request),
                                    nativeIssueResponseCapture(response)));
}

void addIssue(IssueDb *issueDb, const HttpResponse &response,
              const QString &genericIssueDataPath, const QString &name,
              const qint32 impact, const QString &identitySuffix)
{
    Issue issue;
    IssueTemplate::applyGeneric(&issue, name, genericIssueDataPath);
    issue.field18 = name;
    issue.field30 = response.url;
    issue.field38 = impact;
    setNativeIdentity(&issue, response, identitySuffix);
    attachNativeHttpCapture(&issue, response);
    issueDb->add(std::move(issue));
}

bool isEligibleResponse(const HttpResponse &response)
{
    const qint64 requestKind = response.request.attribute(
        static_cast<QNetworkRequest::Attribute>(1012)).toLongLong();
    return response.statusCode > 0 && (requestKind == 1 || requestKind == 2);
}

bool htmlResponse(const HttpResponse &response)
{
    return headerValue(response, QByteArrayLiteral("Content-Type")).trimmed()
        .toLower().startsWith(QByteArrayLiteral("text/html"));
}

} // namespace

void PassiveChecks::processErrorDetection(const NetworkManager::ResponsePointer &response,
                                          IssueDb *issueDb, const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if ((flags & 8) != 8)
        return;

    // Detect server errors (500-599)
    if (response->statusCode >= 500 && response->statusCode <= 599) {
        QString name;
        switch (response->statusCode) {
        case 500: name = QStringLiteral("Internal Server Error"); break;
        case 501: name = QStringLiteral("Not Implemented Error"); break;
        case 502: name = QStringLiteral("Bad Gateway Error"); break;
        case 503: name = QStringLiteral("Service Unavailable Error"); break;
        case 504: name = QStringLiteral("Gateway Timeout Error"); break;
        default: name = QStringLiteral("Server Error (%1)").arg(response->statusCode); break;
        }
        addIssue(issueDb, *response, genericIssueDataPath, name, 2,
                 QStringLiteral("errordetection@%1").arg(response->statusCode));
    }
}

void PassiveChecks::processPassive(const NetworkManager::ResponsePointer &response,
                                   IssueDb *issueDb, const QString &selection,
                                   const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if ((flags & 8) != 8)
        return;

    if (!isEligibleResponse(*response))
        return;

    const bool checkHttps = selection.contains(QStringLiteral("https"));
    const bool checkPassive = selection.contains(QStringLiteral("passive"));
    const bool checkSubresource = selection.contains(QStringLiteral("subresource")) ||
                                  selection.contains(QStringLiteral("integrity"));

    // BREACH attack detection - compressed HTTPS response with user input reflected
    if (checkPassive && response->url.scheme() == QStringLiteral("https")) {
        const QByteArray encoding = headerValue(*response, QByteArrayLiteral("Content-Encoding"));
        if (encoding.contains("gzip") || encoding.contains("deflate") || encoding.contains("br")) {
            // Check if response might reflect user input (has forms or query parameters)
            const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
            if (body.contains("<form") || response->url.hasQuery()) {
                addIssue(issueDb, *response, genericIssueDataPath,
                         QStringLiteral("BREACH Attack Possible"), 3,
                         QStringLiteral("passive@breach"));
            }
        }
    }

    // Mixed content detection for HTTPS pages
    if (checkHttps && response->url.scheme() == QStringLiteral("https") && htmlResponse(*response)) {
        const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
        const QString html = QString::fromUtf8(body);

        // Check for HTTP resources in HTTPS page
        static const QRegularExpression httpResource(
            QStringLiteral("(?:src|href)\\s*=\\s*[\"']http://"),
            QRegularExpression::CaseInsensitiveOption);
        if (httpResource.match(html).hasMatch()) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Mixed Content Found"), 3,
                     QStringLiteral("passive@mixedcontent"));
        }
    }

    // Subresource integrity check
    if (checkSubresource && htmlResponse(*response)) {
        const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
        const QString html = QString::fromUtf8(body);

        // Check for external scripts without integrity attribute
        static const QRegularExpression externalScript(
            QStringLiteral("<script[^>]+src\\s*=\\s*[\"']https?://[^\"']+[\"'][^>]*>"),
            QRegularExpression::CaseInsensitiveOption);
        auto it = externalScript.globalMatch(html);
        while (it.hasNext()) {
            const QString match = it.next().captured(0);
            if (!match.contains(QStringLiteral("integrity"))) {
                addIssue(issueDb, *response, genericIssueDataPath,
                         QStringLiteral("Subresource Integrity is Missing"), 4,
                         QStringLiteral("passive@sri"));
                break;
            }
        }
    }
}

void PassiveChecks::processSecretLeak(const NetworkManager::ResponsePointer &response,
                                      IssueDb *issueDb, const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if ((flags & 8) != 8)
        return;

    if (!isEligibleResponse(*response))
        return;

    const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
    if (body.isEmpty())
        return;

    const QString content = QString::fromUtf8(body);

    // Common secret patterns
    static const QList<QPair<QRegularExpression, QString>> patterns = {
        // API Keys
        {QRegularExpression(QStringLiteral("(?:api[_-]?key|apikey)\\s*[:=]\\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?"),
                            QRegularExpression::CaseInsensitiveOption),
         QStringLiteral("API Key Exposed")},
        // AWS Access Key
        {QRegularExpression(QStringLiteral("AKIA[0-9A-Z]{16}")),
         QStringLiteral("AWS Access Key Exposed")},
        // Private Key
        {QRegularExpression(QStringLiteral("-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")),
         QStringLiteral("Private Key Exposed")},
        // Password in URL or config
        {QRegularExpression(QStringLiteral("(?:password|passwd|pwd)\\s*[:=]\\s*['\"]([^'\"\\s]{4,})['\"]"),
                            QRegularExpression::CaseInsensitiveOption),
         QStringLiteral("Password Exposed")},
        // Database connection string
        {QRegularExpression(QStringLiteral("(?:mysql|postgres|mongodb|redis)://[^\\s<>\"']+:[^\\s<>\"']+@"),
                            QRegularExpression::CaseInsensitiveOption),
         QStringLiteral("Database Connection String Exposed")},
        // JWT Token
        {QRegularExpression(QStringLiteral("eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*")),
         QStringLiteral("JWT Token Exposed")},
        // Email addresses (potential data leak)
        {QRegularExpression(QStringLiteral("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")),
         QStringLiteral("Email Address Disclosed")},
        // Internal IP addresses
        {QRegularExpression(QStringLiteral("(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)[0-9.]+(?::[0-9]+)?")),
         QStringLiteral("Internal IP Address Disclosed")},
        // Stack trace / path disclosure
        {QRegularExpression(QStringLiteral("(?:at |in |File \")[A-Za-z]:\\\\[^\"\\n]+|/(?:home|var|usr|opt)/[^\\s<>\"']+\\.(?:php|py|rb|js|java)")),
         QStringLiteral("Path Disclosure")},
    };

    for (const auto &pattern : patterns) {
        const QRegularExpressionMatch match = pattern.first.match(content);
        if (match.hasMatch()) {
            // Skip email addresses in HTML that are likely intentional (mailto links, etc.)
            if (pattern.second == QStringLiteral("Email Address Disclosed")) {
                // Only report if there are many emails (likely a data dump)
                auto it = pattern.first.globalMatch(content);
                int count = 0;
                while (it.hasNext() && count < 5) {
                    it.next();
                    ++count;
                }
                if (count < 5)
                    continue;
            }

            addIssue(issueDb, *response, genericIssueDataPath,
                     pattern.second, pattern.second.contains("Key") || pattern.second.contains("Password") ? 1 : 3,
                     QStringLiteral("secretleak@%1").arg(pattern.second.toLower().replace(' ', '_')));
        }
    }
}

void PassiveChecks::processRobotsTxt(const NetworkManager::ResponsePointer &response,
                                     IssueDb *issueDb, const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if ((flags & 8) != 8)
        return;

    // Only process robots.txt files
    const QString path = response->url.path();
    if (!path.endsWith(QStringLiteral("/robots.txt"), Qt::CaseInsensitive)
        && path != QStringLiteral("/robots.txt"))
        return;

    if (response->statusCode < 200 || response->statusCode >= 300)
        return;

    const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
    const QString content = QString::fromUtf8(body);

    // Check for sensitive paths in Disallow directives
    static const QRegularExpression disallowPattern(
        QStringLiteral("Disallow\\s*:\\s*([^\\n]+)"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);

    static const QList<QString> sensitiveKeywords = {
        QStringLiteral("admin"), QStringLiteral("backup"), QStringLiteral("config"),
        QStringLiteral("database"), QStringLiteral("db"), QStringLiteral("secret"),
        QStringLiteral("private"), QStringLiteral("internal"), QStringLiteral("test"),
        QStringLiteral("staging"), QStringLiteral("dev"), QStringLiteral("api"),
        QStringLiteral("password"), QStringLiteral("login"), QStringLiteral("auth"),
        QStringLiteral("upload"), QStringLiteral("tmp"), QStringLiteral("temp"),
        QStringLiteral("log"), QStringLiteral(".git"), QStringLiteral(".svn"),
        QStringLiteral("phpmyadmin"), QStringLiteral("wp-admin"), QStringLiteral("cpanel")
    };

    auto it = disallowPattern.globalMatch(content);
    bool hasHiddenResource = false;
    while (it.hasNext()) {
        const QString disallowed = it.next().captured(1).trimmed().toLower();
        // Any non-trivial disallow is a hidden resource
        if (!disallowed.isEmpty() && disallowed != QStringLiteral("/") && !hasHiddenResource) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Hidden Resource in Robots.txt"), 4,
                     QStringLiteral("robotstxt@hidden"));
            hasHiddenResource = true;
        }
        for (const QString &keyword : sensitiveKeywords) {
            if (disallowed.contains(keyword)) {
                addIssue(issueDb, *response, genericIssueDataPath,
                         QStringLiteral("Sensitive Path in Robots.txt"), 4,
                         QStringLiteral("robotstxt@%1").arg(keyword));
                break;
            }
        }
    }

    // Check for path disclosure (full server paths)
    static const QRegularExpression pathPattern(
        QStringLiteral("(?:/home/|/var/|/usr/|/opt/|[A-Za-z]:\\\\)[^\\s\\n]+"),
        QRegularExpression::CaseInsensitiveOption);
    if (pathPattern.match(content).hasMatch()) {
        addIssue(issueDb, *response, genericIssueDataPath,
                 QStringLiteral("Path Disclosure in Robots.txt"), 4,
                 QStringLiteral("robotstxt@pathdisclosure"));
    }
}

void PassiveChecks::processLoginPage(const NetworkManager::ResponsePointer &response,
                                     IssueDb *issueDb, const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if ((flags & 8) != 8)
        return;

    if (!isEligibleResponse(*response) || !htmlResponse(*response))
        return;

    const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
    const QString html = QString::fromUtf8(body);

    // Check for login forms
    static const QRegularExpression passwordInput(
        QStringLiteral("<input[^>]+type\\s*=\\s*['\"]password['\"][^>]*>"),
        QRegularExpression::CaseInsensitiveOption);

    if (passwordInput.match(html).hasMatch()) {
        // Check if it's an unreferenced login page (no direct links from other pages)
        const QString path = response->url.path().toLower();
        if (path.contains(QStringLiteral("login")) ||
            path.contains(QStringLiteral("signin")) ||
            path.contains(QStringLiteral("admin")) ||
            path.contains(QStringLiteral("auth"))) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Unreferenced Login Page Found"), 4,
                     QStringLiteral("loginpage@found"));
        } else {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Login Page Found"), 4,
                     QStringLiteral("loginpage@generic"));
        }

        // Check if login form is over HTTP (not HTTPS)
        if (response->url.scheme() == QStringLiteral("http")) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Login Form Over HTTP"), 1,
                     QStringLiteral("loginpage@http"));
        }

        // Check for autocomplete enabled on password fields
        static const QRegularExpression autocompleteOff(
            QStringLiteral("<input[^>]+type\\s*=\\s*['\"]password['\"][^>]*autocomplete\\s*=\\s*['\"](?:off|new-password)['\"]"),
            QRegularExpression::CaseInsensitiveOption);
        static const QRegularExpression autocompleteOffReverse(
            QStringLiteral("<input[^>]+autocomplete\\s*=\\s*['\"](?:off|new-password)['\"][^>]*type\\s*=\\s*['\"]password['\"]"),
            QRegularExpression::CaseInsensitiveOption);
        if (!autocompleteOff.match(html).hasMatch() && !autocompleteOffReverse.match(html).hasMatch()) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Auto Complete Enabled Password Input"), 4,
                     QStringLiteral("loginpage@autocomplete"));
        }
    }
}

void PassiveChecks::processFingerprint(const NetworkManager::ResponsePointer &response,
                                       IssueDb *issueDb, const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if ((flags & 8) != 8)
        return;

    if (!isEligibleResponse(*response))
        return;

    // Check Server header for version information
    const QByteArray server = headerValue(*response, QByteArrayLiteral("Server"));
    if (!server.isEmpty()) {
        static const QRegularExpression versionPattern(
            QStringLiteral("(?:Apache|nginx|IIS|Tomcat|lighttpd|LiteSpeed)[/\\s]+([0-9.]+)"),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch match = versionPattern.match(QString::fromUtf8(server));
        if (match.hasMatch()) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Web Server Version Disclosed"), 4,
                     QStringLiteral("fingerprint@server"));
        }
    }

    // Check X-Powered-By header
    const QByteArray poweredBy = headerValue(*response, QByteArrayLiteral("X-Powered-By"));
    if (!poweredBy.isEmpty()) {
        static const QRegularExpression techPattern(
            QStringLiteral("(?:PHP|ASP\\.NET|Express|Ruby|Python|Java)[/\\s]*([0-9.]+)?"),
            QRegularExpression::CaseInsensitiveOption);
        if (techPattern.match(QString::fromUtf8(poweredBy)).hasMatch()) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Technology Stack Disclosed"), 4,
                     QStringLiteral("fingerprint@poweredby"));
        }
    }

    // Check for outdated technologies in response body (if HTML)
    if (htmlResponse(*response)) {
        const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
        const QString html = QString::fromUtf8(body);

        // Check for meta generator tag
        static const QRegularExpression generatorPattern(
            QStringLiteral("<meta[^>]+name\\s*=\\s*['\"]generator['\"][^>]+content\\s*=\\s*['\"]([^'\"]+)['\"]"),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch genMatch = generatorPattern.match(html);
        if (genMatch.hasMatch()) {
            const QString generator = genMatch.captured(1);
            if (generator.contains(QStringLiteral("WordPress"), Qt::CaseInsensitive) ||
                generator.contains(QStringLiteral("Drupal"), Qt::CaseInsensitive) ||
                generator.contains(QStringLiteral("Joomla"), Qt::CaseInsensitive)) {
                addIssue(issueDb, *response, genericIssueDataPath,
                         QStringLiteral("CMS Version Disclosed"), 4,
                         QStringLiteral("fingerprint@cms"));
            }
        }
    }
}

void PassiveChecks::processHttps(const NetworkManager::ResponsePointer &response,
                                 IssueDb *issueDb, const QString &selection,
                                 const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if ((flags & 8) != 8)
        return;

    // Only check HTTPS URLs
    if (response->url.scheme() != QStringLiteral("https"))
        return;

    const bool checkOthers = selection.contains(QStringLiteral("others"));

    // Check for weak cipher suites or TLS issues (indicated by specific headers/behavior)
    if (checkOthers) {
        // Check if the response has any TLS-related headers indicating issues
        const QByteArray publicKeyPins = headerValue(*response, QByteArrayLiteral("Public-Key-Pins"));
        const QByteArray expectCT = headerValue(*response, QByteArrayLiteral("Expect-CT"));

        // No HPKP deprecation warning - it's deprecated anyway
        // But warn about missing Expect-CT for certificate transparency
        if (expectCT.isEmpty()) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Expect-CT Header Missing"), 4,
                     QStringLiteral("https@expect-ct"));
        }
    }
}

void PassiveChecks::processHttpsRedirection(const NetworkManager::ResponsePointer &response,
                                            IssueDb *issueDb, const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if ((flags & 8) != 8)
        return;

    // Check if HTTP URLs don't redirect to HTTPS
    if (response->url.scheme() == QStringLiteral("http")) {
        // Check if this is a redirect to HTTPS
        bool redirectsToHttps = false;
        const QByteArray location = headerValue(*response, QByteArrayLiteral("Location"));
        if (!location.isEmpty() && QString::fromUtf8(location).startsWith(QStringLiteral("https://"))) {
            redirectsToHttps = true;
        }

        if (!redirectsToHttps && response->statusCode >= 200 && response->statusCode < 300) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("HTTP to HTTPS Redirection Missing"), 3,
                     QStringLiteral("httpsredirection@missing"));
        }
    }
}

void PassiveChecks::processBrokenLink(const NetworkManager::ResponsePointer &response,
                                      IssueDb *issueDb, const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    // Detect 404 responses
    if (response->statusCode == 404) {
        // Use URL path as identity suffix to allow multiple broken links
        const QString path = response->url.path();
        addIssue(issueDb, *response, genericIssueDataPath,
                 QStringLiteral("Broken Link"), 4,
                 QStringLiteral("brokenlink@%1").arg(path));
    }
}

void PassiveChecks::processTlsVersion(const NetworkManager::ResponsePointer &response,
                                      IssueDb *issueDb, const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    // Only check HTTPS URLs
    if (response->url.scheme() != QStringLiteral("https"))
        return;

    // Check for TLS version issues via response headers or SSL info
    // Note: Full TLS version detection requires SSL socket inspection
    // This is a simplified check based on server behavior indicators
    const QByteArray server = headerValue(*response, QByteArrayLiteral("Server"));
    const QString serverStr = QString::fromUtf8(server).toLower();

    // Old Apache/nginx versions often support TLS 1.0
    static const QRegularExpression oldApache(QStringLiteral("apache/2\\.[0-2]"),
                                              QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression oldNginx(QStringLiteral("nginx/1\\.[0-9]\\."),
                                             QRegularExpression::CaseInsensitiveOption);

    if (oldApache.match(serverStr).hasMatch() || oldNginx.match(serverStr).hasMatch()) {
        addIssue(issueDb, *response, genericIssueDataPath,
                 QStringLiteral("TLS 1.0 enabled"), 3,
                 QStringLiteral("tls@1.0"));
    }
}
