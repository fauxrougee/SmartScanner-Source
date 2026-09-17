#pragma once

#include <QString>
#include <QStringList>
#include <QMap>
#include <QRegularExpression>
#include <QList>

namespace AdvancedAnalysis {

// Deserialization pattern
struct DeserializationPattern {
    QString language;
    QString signature;
    QString description;
};

// JWT vulnerability
struct JwtVulnerability {
    QString type;
    QString description;
    QString testPayload;
    double confidence;
};

// API endpoint pattern
struct ApiEndpointPattern {
    QString type;
    QRegularExpression pattern;
    QString description;
};

// Sensitive data pattern
struct SensitiveDataPattern {
    QString type;
    QRegularExpression regex;
    QString description;
    double confidence;
};

// CORS misconfiguration
struct CorsMisconfiguration {
    QString type;
    QString indicator;
    QString description;
    double severity;
};

// OAuth misconfiguration
struct OAuthMisconfiguration {
    QString type;
    QString description;
    double severity;
};

// HTML injection context
struct HtmlInjectionContext {
    QString type;
    QString description;
    QString payload;
};

// File upload vulnerability
struct FileUploadVulnerability {
    QString type;
    QString payload;
    QString description;
};

// Finding structure
struct Finding {
    QString type;
    QString subtype;
    QString description;
    QString evidence;
    double confidence = 0.0;
    int lineNumber = -1;
};

// Analysis result
struct AnalysisResult {
    int statusCode = 0;
    QList<Finding> findings;
    QStringList warnings;
    QStringList info;
};

// DOM XSS patterns
QStringList getDomXssSourcePatterns();
QStringList getDomXssSinkPatterns();

// Prototype pollution
QStringList getPrototypePollutionPatterns();

// Deserialization
QList<DeserializationPattern> getDeserializationPatterns();

// JWT
QList<JwtVulnerability> getJwtVulnerabilities();

// GraphQL
QStringList getGraphQLIntrospectionQueries();

// API patterns
QList<ApiEndpointPattern> getApiEndpointPatterns();

// Sensitive data
QList<SensitiveDataPattern> getSensitiveDataPatterns();

// CORS
QList<CorsMisconfiguration> getCorsMisconfigurations();

// HTTP request smuggling
QStringList getRequestSmugglingPayloads();

// Cache poisoning
QStringList getCachePoisoningHeaders();

// OAuth
QList<OAuthMisconfiguration> getOAuthMisconfigurations();

// LDAP injection
QStringList getLdapInjectionPayloads();

// NoSQL injection
QStringList getNoSqlInjectionPayloads();

// WebSocket
QStringList getWebSocketVulnerabilities();

// SSRF bypass
QStringList getSsrfBypassPayloads();

// HTML injection contexts
QList<HtmlInjectionContext> getHtmlInjectionContexts();

// File upload
QList<FileUploadVulnerability> getFileUploadVulnerabilities();

// Race conditions
QStringList getRaceConditionScenarios();

// Business logic
QStringList getBusinessLogicVulnerabilities();

// Main analysis function
AnalysisResult analyzeResponse(const QString &body, const QMap<QString, QString> &headers, int statusCode);

} // namespace AdvancedAnalysis
