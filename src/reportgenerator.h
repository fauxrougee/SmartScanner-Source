#ifndef REPORTGENERATOR_H
#define REPORTGENERATOR_H

#include <QString>
#include <QStringList>
#include <QHash>
#include <QList>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QXmlStreamWriter>

struct VulnerabilityReport {
    QString id;
    QString title;
    QString severity;
    QString description;
    QString url;
    QString parameter;
    QString payload;
    QString evidence;
    QString remediation;
    QString cvss;
    QString cwe;
    QDateTime discoveredAt;
};

struct ScanReport {
    QString scanId;
    QString targetUrl;
    QDateTime startTime;
    QDateTime endTime;
    int totalRequests;
    int totalVulnerabilities;
    QList<VulnerabilityReport> vulnerabilities;
    QHash<QString, int> severityCounts;
    QHash<QString, int> categoryCounts;
};

class ReportGenerator {
public:
    static QString generateHtmlReport(const ScanReport &report);
    static QString generateJsonReport(const ScanReport &report);
    static QString generateXmlReport(const ScanReport &report);
    static QString generateMarkdownReport(const ScanReport &report);
    static QString generateCsvReport(const ScanReport &report);
    static QString generateTextReport(const ScanReport &report);
    static QString generatePdfReportContent(const ScanReport &report);

    static QString generateExecutiveSummary(const ScanReport &report);
    static QString generateTechnicalDetails(const ScanReport &report);
    static QString generateRemediationPlan(const ScanReport &report);

    static QJsonObject toJsonObject(const VulnerabilityReport &vuln);
    static QJsonObject toJsonObject(const ScanReport &report);
    static QString severityToColor(const QString &severity);
    static QString severityToBadge(const QString &severity);
    static int severityToScore(const QString &severity);

    static QString getHtmlStyles();
    static QString getHtmlHeader(const QString &title);
    static QString getHtmlFooter();
    static QString escapeHtml(const QString &text);
    static QString escapeXml(const QString &text);
    static QString escapeCsv(const QString &text);

    static QStringList getReportTemplates();
    static QString applyTemplate(const QString &templateName, const ScanReport &report);

    static QString generateOwaspTop10Summary(const ScanReport &report);
    static QString generateCweTop25Summary(const ScanReport &report);
    static QString generateComplianceReport(const ScanReport &report, const QString &standard);
};

#endif // REPORTGENERATOR_H
