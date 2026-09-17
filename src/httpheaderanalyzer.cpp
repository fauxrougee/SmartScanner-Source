#include "httpheaderanalyzer.h"
#include <QRegularExpression>

namespace {

const QStringList securityHeaders = {
    QStringLiteral("Strict-Transport-Security"),
    QStringLiteral("Content-Security-Policy"),
    QStringLiteral("X-Content-Type-Options"),
    QStringLiteral("X-Frame-Options"),
    QStringLiteral("X-XSS-Protection"),
    QStringLiteral("Referrer-Policy"),
    QStringLiteral("Permissions-Policy"),
    QStringLiteral("Feature-Policy"),
    QStringLiteral("Cross-Origin-Embedder-Policy"),
    QStringLiteral("Cross-Origin-Opener-Policy"),
    QStringLiteral("Cross-Origin-Resource-Policy"),
    QStringLiteral("X-Permitted-Cross-Domain-Policies"),
    QStringLiteral("Expect-CT"),
    QStringLiteral("Clear-Site-Data")
};

const QStringList infoLeakHeaders = {
    QStringLiteral("Server"),
    QStringLiteral("X-Powered-By"),
    QStringLiteral("X-AspNet-Version"),
    QStringLiteral("X-AspNetMvc-Version"),
    QStringLiteral("X-Runtime"),
    QStringLiteral("X-Version"),
    QStringLiteral("X-Generator"),
    QStringLiteral("X-Drupal-Cache"),
    QStringLiteral("X-Drupal-Dynamic-Cache"),
    QStringLiteral("X-Varnish"),
    QStringLiteral("Via"),
    QStringLiteral("X-Backend-Server"),
    QStringLiteral("X-Cache"),
    QStringLiteral("X-Cache-Hits"),
    QStringLiteral("X-Served-By"),
    QStringLiteral("X-Timer")
};

const QStringList cachingHeaders = {
    QStringLiteral("Cache-Control"),
    QStringLiteral("Pragma"),
    QStringLiteral("Expires"),
    QStringLiteral("ETag"),
    QStringLiteral("Last-Modified"),
    QStringLiteral("Vary"),
    QStringLiteral("Age"),
    QStringLiteral("Surrogate-Control")
};

bool hasHeader(const QMap<QString, QString> &headers, const QString &name) {
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
        if (it.key().compare(name, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}

QString getHeader(const QMap<QString, QString> &headers, const QString &name) {
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
        if (it.key().compare(name, Qt::CaseInsensitive) == 0) {
            return it.value();
        }
    }
    return QString();
}

} // anonymous namespace


QList<HttpHeaderAnalyzer::Finding> HttpHeaderAnalyzer::analyze(const QMap<QString, QString> &headers) const
{
    QList<Finding> findings;

    if (!hasHeader(headers, QStringLiteral("Strict-Transport-Security"))) {
        findings.append({
            QStringLiteral("Strict-Transport-Security"),
            QStringLiteral("Missing HSTS header - site may be vulnerable to protocol downgrade attacks"),
            QStringLiteral("Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"),
            Severity::Medium
        });
    } else {
        QString hsts = getHeader(headers, QStringLiteral("Strict-Transport-Security"));
        QRegularExpression maxAgeRe(QStringLiteral("max-age=(\\d+)"), QRegularExpression::CaseInsensitiveOption);
        QRegularExpressionMatch match = maxAgeRe.match(hsts);
        if (match.hasMatch()) {
            int maxAge = match.captured(1).toInt();
            if (maxAge < 31536000) {
                findings.append({
                    QStringLiteral("Strict-Transport-Security"),
                    QStringLiteral("HSTS max-age is less than recommended (1 year)"),
                    QStringLiteral("Increase max-age to at least 31536000 (1 year)"),
                    Severity::Low
                });
            }
        }
        if (!hsts.contains(QStringLiteral("includeSubDomains"), Qt::CaseInsensitive)) {
            findings.append({
                QStringLiteral("Strict-Transport-Security"),
                QStringLiteral("HSTS does not include subdomains"),
                QStringLiteral("Add 'includeSubDomains' directive"),
                Severity::Low
            });
        }
    }

    if (!hasHeader(headers, QStringLiteral("Content-Security-Policy"))) {
        findings.append({
            QStringLiteral("Content-Security-Policy"),
            QStringLiteral("Missing CSP header - site may be vulnerable to XSS and data injection attacks"),
            QStringLiteral("Implement a Content-Security-Policy header"),
            Severity::Medium
        });
    } else {
        QString csp = getHeader(headers, QStringLiteral("Content-Security-Policy"));
        if (csp.contains(QStringLiteral("unsafe-inline"))) {
            findings.append({
                QStringLiteral("Content-Security-Policy"),
                QStringLiteral("CSP allows 'unsafe-inline' which weakens XSS protection"),
                QStringLiteral("Remove 'unsafe-inline' and use nonces or hashes"),
                Severity::Medium
            });
        }
        if (csp.contains(QStringLiteral("unsafe-eval"))) {
            findings.append({
                QStringLiteral("Content-Security-Policy"),
                QStringLiteral("CSP allows 'unsafe-eval' which enables dynamic code execution"),
                QStringLiteral("Remove 'unsafe-eval' if possible"),
                Severity::Medium
            });
        }
        if (csp.contains(QStringLiteral("*"))) {
            findings.append({
                QStringLiteral("Content-Security-Policy"),
                QStringLiteral("CSP uses wildcard source which may be too permissive"),
                QStringLiteral("Replace wildcards with specific domains"),
                Severity::Low
            });
        }
    }

    if (!hasHeader(headers, QStringLiteral("X-Content-Type-Options"))) {
        findings.append({
            QStringLiteral("X-Content-Type-Options"),
            QStringLiteral("Missing X-Content-Type-Options header - browser may MIME-sniff responses"),
            QStringLiteral("Add 'X-Content-Type-Options: nosniff'"),
            Severity::Low
        });
    } else {
        QString xcto = getHeader(headers, QStringLiteral("X-Content-Type-Options"));
        if (!xcto.contains(QStringLiteral("nosniff"), Qt::CaseInsensitive)) {
            findings.append({
                QStringLiteral("X-Content-Type-Options"),
                QStringLiteral("X-Content-Type-Options should be set to 'nosniff'"),
                QStringLiteral("Set value to 'nosniff'"),
                Severity::Low
            });
        }
    }

    if (!hasHeader(headers, QStringLiteral("X-Frame-Options"))) {
        findings.append({
            QStringLiteral("X-Frame-Options"),
            QStringLiteral("Missing X-Frame-Options header - site may be vulnerable to clickjacking"),
            QStringLiteral("Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"),
            Severity::Medium
        });
    } else {
        QString xfo = getHeader(headers, QStringLiteral("X-Frame-Options"));
        if (xfo.contains(QStringLiteral("ALLOW-FROM"), Qt::CaseInsensitive)) {
            findings.append({
                QStringLiteral("X-Frame-Options"),
                QStringLiteral("ALLOW-FROM directive is deprecated and not supported by modern browsers"),
                QStringLiteral("Use CSP frame-ancestors directive instead"),
                Severity::Low
            });
        }
    }

    if (!hasHeader(headers, QStringLiteral("Referrer-Policy"))) {
        findings.append({
            QStringLiteral("Referrer-Policy"),
            QStringLiteral("Missing Referrer-Policy header - referrer information may leak to external sites"),
            QStringLiteral("Add 'Referrer-Policy: strict-origin-when-cross-origin'"),
            Severity::Low
        });
    }

    if (!hasHeader(headers, QStringLiteral("Permissions-Policy")) &&
        !hasHeader(headers, QStringLiteral("Feature-Policy"))) {
        findings.append({
            QStringLiteral("Permissions-Policy"),
            QStringLiteral("Missing Permissions-Policy header - browser features not restricted"),
            QStringLiteral("Add Permissions-Policy to restrict browser features"),
            Severity::Info
        });
    }

    for (const QString &infoHeader : infoLeakHeaders) {
        if (hasHeader(headers, infoHeader)) {
            QString value = getHeader(headers, infoHeader);
            if (!value.isEmpty()) {
                findings.append({
                    infoHeader,
                    QStringLiteral("Header discloses server/technology information: %1").arg(value),
                    QStringLiteral("Remove or obfuscate this header"),
                    Severity::Info
                });
            }
        }
    }

    QString setCookie = getHeader(headers, QStringLiteral("Set-Cookie"));
    if (!setCookie.isEmpty()) {
        if (!setCookie.contains(QStringLiteral("HttpOnly"), Qt::CaseInsensitive)) {
            findings.append({
                QStringLiteral("Set-Cookie"),
                QStringLiteral("Cookie missing HttpOnly flag - vulnerable to XSS cookie theft"),
                QStringLiteral("Add HttpOnly flag to cookies"),
                Severity::Medium
            });
        }
        if (!setCookie.contains(QStringLiteral("Secure"), Qt::CaseInsensitive)) {
            findings.append({
                QStringLiteral("Set-Cookie"),
                QStringLiteral("Cookie missing Secure flag - may be sent over unencrypted connections"),
                QStringLiteral("Add Secure flag to cookies"),
                Severity::Medium
            });
        }
        if (!setCookie.contains(QStringLiteral("SameSite"), Qt::CaseInsensitive)) {
            findings.append({
                QStringLiteral("Set-Cookie"),
                QStringLiteral("Cookie missing SameSite attribute - may be vulnerable to CSRF"),
                QStringLiteral("Add SameSite=Strict or SameSite=Lax attribute"),
                Severity::Medium
            });
        }
    }

    QString cacheControl = getHeader(headers, QStringLiteral("Cache-Control"));
    QString pragma = getHeader(headers, QStringLiteral("Pragma"));
    if (cacheControl.isEmpty() && pragma.isEmpty()) {
        findings.append({
            QStringLiteral("Cache-Control"),
            QStringLiteral("No caching headers present - sensitive data may be cached"),
            QStringLiteral("Add 'Cache-Control: no-store, no-cache, must-revalidate'"),
            Severity::Low
        });
    }

    QString accessControl = getHeader(headers, QStringLiteral("Access-Control-Allow-Origin"));
    if (accessControl == QStringLiteral("*")) {
        findings.append({
            QStringLiteral("Access-Control-Allow-Origin"),
            QStringLiteral("CORS allows all origins which may be too permissive"),
            QStringLiteral("Restrict to specific trusted origins"),
            Severity::Medium
        });
    }

    QString accessControlCreds = getHeader(headers, QStringLiteral("Access-Control-Allow-Credentials"));
    if (accessControlCreds.compare(QStringLiteral("true"), Qt::CaseInsensitive) == 0 &&
        accessControl == QStringLiteral("*")) {
        findings.append({
            QStringLiteral("Access-Control-Allow-Credentials"),
            QStringLiteral("CORS misconfiguration - credentials allowed with wildcard origin"),
            QStringLiteral("Do not use wildcard origin with credentials"),
            Severity::High
        });
    }

    return findings;
}

bool HttpHeaderAnalyzer::hasSecurityIssues(const QMap<QString, QString> &headers) const
{
    QList<Finding> findings = analyze(headers);
    for (const Finding &f : findings) {
        if (f.severity >= Severity::Medium) {
            return true;
        }
    }
    return false;
}

QStringList HttpHeaderAnalyzer::getSecurityHeaders()
{
    return securityHeaders;
}

QStringList HttpHeaderAnalyzer::getInformationLeakageHeaders()
{
    return infoLeakHeaders;
}

QStringList HttpHeaderAnalyzer::getCachingHeaders()
{
    return cachingHeaders;
}

QString HttpHeaderAnalyzer::severityName(Severity sev)
{
    switch (sev) {
    case Severity::Info: return QStringLiteral("Informational");
    case Severity::Low: return QStringLiteral("Low");
    case Severity::Medium: return QStringLiteral("Medium");
    case Severity::High: return QStringLiteral("High");
    case Severity::Critical: return QStringLiteral("Critical");
    default: return QStringLiteral("Unknown");
    }
}
