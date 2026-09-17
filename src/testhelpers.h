#pragma once

#include <QString>
#include <QStringList>
#include <QMap>
#include <QRegularExpression>
#include <QUrl>

namespace TestHelpers {

// Content types
enum class ContentType {
    Unknown,
    Html,
    Json,
    Xml,
    JavaScript,
    Css,
    Image,
    Pdf
};

// Technology stack info
struct TechStack {
    QString webServer;
    QString language;
    QString framework;
    QString cms;
    QString jsFramework;
};

// SQL injection pattern
struct SqlInjectionPattern {
    QString dbType;
    QRegularExpression pattern;
    double confidence;
};

// XSS pattern
struct XssPattern {
    QString type;
    QRegularExpression pattern;
    double confidence;
};

// Cookie security info
struct CookieSecurityInfo {
    bool hasSecure = false;
    bool hasHttpOnly = false;
    bool hasSameSite = false;
    bool hasPath = false;
    bool hasDomain = false;
    bool hasExpires = false;
};

// URL manipulation
QString normalizeUrl(const QString &url);
QString extractDomain(const QString &url);
QString extractPath(const QString &url);
QStringList extractParameters(const QString &url);

// Hash generation
QString generateUrlHash(const QString &url);
QString generateResponseHash(const QByteArray &body);

// Content detection
ContentType detectContentType(const QString &contentTypeHeader);

// Technology fingerprinting
TechStack detectTechnology(const QString &body, const QMap<QString, QString> &headers);

// Pattern retrieval
QList<SqlInjectionPattern> getSqlInjectionPatterns();
QList<XssPattern> getXssPatterns();

// Payload generation
QStringList getPathTraversalPayloads();
QStringList getSsrfPayloads();
QStringList getCommandInjectionPayloads();
QStringList getXxePayloads();
QStringList getSstiPayloads();

// Response analysis
bool containsSensitiveData(const QString &content);
bool isErrorPage(const QString &content, int statusCode);
QStringList getMissingSecurityHeaders(const QMap<QString, QString> &headers);
CookieSecurityInfo analyzeCookie(const QString &cookieHeader);

// Version utilities
int compareVersions(const QString &v1, const QString &v2);
QString extractVersion(const QString &text);

// Rate limiting and WAF detection
bool isRateLimited(int statusCode, const QMap<QString, QString> &headers);
QString detectWaf(const QString &body, const QMap<QString, QString> &headers, int statusCode);

} // namespace TestHelpers
