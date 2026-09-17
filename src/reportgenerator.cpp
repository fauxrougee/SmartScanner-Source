#include "reportgenerator.h"
#include <QJsonDocument>
#include <QTextStream>

QString ReportGenerator::generateHtmlReport(const ScanReport &report) {
    QString html;
    QTextStream out(&html);

    out << getHtmlHeader(QStringLiteral("Security Scan Report - ") + report.targetUrl);
    out << getHtmlStyles();

    out << QStringLiteral("<body>\n");
    out << QStringLiteral("<div class=\"container\">\n");
    out << QStringLiteral("<h1>Security Scan Report</h1>\n");

    out << QStringLiteral("<div class=\"summary-box\">\n");
    out << QStringLiteral("<h2>Scan Summary</h2>\n");
    out << QStringLiteral("<table class=\"summary-table\">\n");
    out << QStringLiteral("<tr><td>Target URL:</td><td>") << escapeHtml(report.targetUrl) << QStringLiteral("</td></tr>\n");
    out << QStringLiteral("<tr><td>Scan ID:</td><td>") << escapeHtml(report.scanId) << QStringLiteral("</td></tr>\n");
    out << QStringLiteral("<tr><td>Start Time:</td><td>") << report.startTime.toString(Qt::ISODate) << QStringLiteral("</td></tr>\n");
    out << QStringLiteral("<tr><td>End Time:</td><td>") << report.endTime.toString(Qt::ISODate) << QStringLiteral("</td></tr>\n");
    out << QStringLiteral("<tr><td>Duration:</td><td>") << QString::number(report.startTime.secsTo(report.endTime)) << QStringLiteral(" seconds</td></tr>\n");
    out << QStringLiteral("<tr><td>Total Requests:</td><td>") << QString::number(report.totalRequests) << QStringLiteral("</td></tr>\n");
    out << QStringLiteral("<tr><td>Vulnerabilities Found:</td><td>") << QString::number(report.totalVulnerabilities) << QStringLiteral("</td></tr>\n");
    out << QStringLiteral("</table>\n");
    out << QStringLiteral("</div>\n");

    out << QStringLiteral("<div class=\"severity-summary\">\n");
    out << QStringLiteral("<h2>Severity Distribution</h2>\n");
    out << QStringLiteral("<div class=\"severity-grid\">\n");

    const QStringList severities = {QStringLiteral("Critical"), QStringLiteral("High"), QStringLiteral("Medium"), QStringLiteral("Low"), QStringLiteral("Info")};
    for (const QString &sev : severities) {
        int count = report.severityCounts.value(sev, 0);
        out << QStringLiteral("<div class=\"severity-card ") << sev.toLower() << QStringLiteral("\">\n");
        out << QStringLiteral("<span class=\"count\">") << QString::number(count) << QStringLiteral("</span>\n");
        out << QStringLiteral("<span class=\"label\">") << sev << QStringLiteral("</span>\n");
        out << QStringLiteral("</div>\n");
    }
    out << QStringLiteral("</div>\n");
    out << QStringLiteral("</div>\n");

    out << QStringLiteral("<div class=\"vulnerabilities\">\n");
    out << QStringLiteral("<h2>Vulnerability Details</h2>\n");

    int vulnNum = 0;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        ++vulnNum;
        out << QStringLiteral("<div class=\"vuln-card ") << vuln.severity.toLower() << QStringLiteral("\">\n");
        out << QStringLiteral("<div class=\"vuln-header\">\n");
        out << QStringLiteral("<span class=\"vuln-num\">") << QString::number(vulnNum) << QStringLiteral("</span>\n");
        out << QStringLiteral("<h3>") << escapeHtml(vuln.title) << QStringLiteral("</h3>\n");
        out << severityToBadge(vuln.severity);
        out << QStringLiteral("</div>\n");

        out << QStringLiteral("<div class=\"vuln-body\">\n");
        out << QStringLiteral("<div class=\"vuln-meta\">\n");
        out << QStringLiteral("<p><strong>ID:</strong> ") << escapeHtml(vuln.id) << QStringLiteral("</p>\n");
        out << QStringLiteral("<p><strong>URL:</strong> <code>") << escapeHtml(vuln.url) << QStringLiteral("</code></p>\n");
        if (!vuln.parameter.isEmpty()) {
            out << QStringLiteral("<p><strong>Parameter:</strong> <code>") << escapeHtml(vuln.parameter) << QStringLiteral("</code></p>\n");
        }
        if (!vuln.cwe.isEmpty()) {
            out << QStringLiteral("<p><strong>CWE:</strong> ") << escapeHtml(vuln.cwe) << QStringLiteral("</p>\n");
        }
        if (!vuln.cvss.isEmpty()) {
            out << QStringLiteral("<p><strong>CVSS:</strong> ") << escapeHtml(vuln.cvss) << QStringLiteral("</p>\n");
        }
        out << QStringLiteral("</div>\n");

        out << QStringLiteral("<div class=\"vuln-description\">\n");
        out << QStringLiteral("<h4>Description</h4>\n");
        out << QStringLiteral("<p>") << escapeHtml(vuln.description) << QStringLiteral("</p>\n");
        out << QStringLiteral("</div>\n");

        if (!vuln.payload.isEmpty()) {
            out << QStringLiteral("<div class=\"vuln-payload\">\n");
            out << QStringLiteral("<h4>Payload</h4>\n");
            out << QStringLiteral("<pre><code>") << escapeHtml(vuln.payload) << QStringLiteral("</code></pre>\n");
            out << QStringLiteral("</div>\n");
        }

        if (!vuln.evidence.isEmpty()) {
            out << QStringLiteral("<div class=\"vuln-evidence\">\n");
            out << QStringLiteral("<h4>Evidence</h4>\n");
            out << QStringLiteral("<pre><code>") << escapeHtml(vuln.evidence) << QStringLiteral("</code></pre>\n");
            out << QStringLiteral("</div>\n");
        }

        if (!vuln.remediation.isEmpty()) {
            out << QStringLiteral("<div class=\"vuln-remediation\">\n");
            out << QStringLiteral("<h4>Remediation</h4>\n");
            out << QStringLiteral("<p>") << escapeHtml(vuln.remediation) << QStringLiteral("</p>\n");
            out << QStringLiteral("</div>\n");
        }

        out << QStringLiteral("</div>\n");
        out << QStringLiteral("</div>\n");
    }

    out << QStringLiteral("</div>\n");
    out << QStringLiteral("</div>\n");
    out << getHtmlFooter();

    return html;
}

QString ReportGenerator::generateJsonReport(const ScanReport &report) {
    QJsonObject obj = toJsonObject(report);
    QJsonDocument doc(obj);
    return QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
}

QString ReportGenerator::generateXmlReport(const ScanReport &report) {
    QString xml;
    QXmlStreamWriter writer(&xml);
    writer.setAutoFormatting(true);
    writer.setAutoFormattingIndent(2);

    writer.writeStartDocument();
    writer.writeStartElement(QStringLiteral("ScanReport"));

    writer.writeStartElement(QStringLiteral("Summary"));
    writer.writeTextElement(QStringLiteral("ScanId"), report.scanId);
    writer.writeTextElement(QStringLiteral("TargetUrl"), report.targetUrl);
    writer.writeTextElement(QStringLiteral("StartTime"), report.startTime.toString(Qt::ISODate));
    writer.writeTextElement(QStringLiteral("EndTime"), report.endTime.toString(Qt::ISODate));
    writer.writeTextElement(QStringLiteral("TotalRequests"), QString::number(report.totalRequests));
    writer.writeTextElement(QStringLiteral("TotalVulnerabilities"), QString::number(report.totalVulnerabilities));
    writer.writeEndElement();

    writer.writeStartElement(QStringLiteral("SeverityCounts"));
    for (auto it = report.severityCounts.constBegin(); it != report.severityCounts.constEnd(); ++it) {
        writer.writeStartElement(QStringLiteral("Severity"));
        writer.writeAttribute(QStringLiteral("level"), it.key());
        writer.writeAttribute(QStringLiteral("count"), QString::number(it.value()));
        writer.writeEndElement();
    }
    writer.writeEndElement();

    writer.writeStartElement(QStringLiteral("Vulnerabilities"));
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        writer.writeStartElement(QStringLiteral("Vulnerability"));
        writer.writeTextElement(QStringLiteral("Id"), vuln.id);
        writer.writeTextElement(QStringLiteral("Title"), vuln.title);
        writer.writeTextElement(QStringLiteral("Severity"), vuln.severity);
        writer.writeTextElement(QStringLiteral("Url"), vuln.url);
        writer.writeTextElement(QStringLiteral("Parameter"), vuln.parameter);
        writer.writeTextElement(QStringLiteral("Description"), vuln.description);
        writer.writeTextElement(QStringLiteral("Payload"), vuln.payload);
        writer.writeTextElement(QStringLiteral("Evidence"), vuln.evidence);
        writer.writeTextElement(QStringLiteral("Remediation"), vuln.remediation);
        writer.writeTextElement(QStringLiteral("CWE"), vuln.cwe);
        writer.writeTextElement(QStringLiteral("CVSS"), vuln.cvss);
        writer.writeTextElement(QStringLiteral("DiscoveredAt"), vuln.discoveredAt.toString(Qt::ISODate));
        writer.writeEndElement();
    }
    writer.writeEndElement();

    writer.writeEndElement();
    writer.writeEndDocument();

    return xml;
}

QString ReportGenerator::generateMarkdownReport(const ScanReport &report) {
    QString md;
    QTextStream out(&md);

    out << QStringLiteral("# Security Scan Report\n\n");
    out << QStringLiteral("## Summary\n\n");
    out << QStringLiteral("| Property | Value |\n");
    out << QStringLiteral("|----------|-------|\n");
    out << QStringLiteral("| Target URL | ") << report.targetUrl << QStringLiteral(" |\n");
    out << QStringLiteral("| Scan ID | ") << report.scanId << QStringLiteral(" |\n");
    out << QStringLiteral("| Start Time | ") << report.startTime.toString(Qt::ISODate) << QStringLiteral(" |\n");
    out << QStringLiteral("| End Time | ") << report.endTime.toString(Qt::ISODate) << QStringLiteral(" |\n");
    out << QStringLiteral("| Total Requests | ") << QString::number(report.totalRequests) << QStringLiteral(" |\n");
    out << QStringLiteral("| Vulnerabilities | ") << QString::number(report.totalVulnerabilities) << QStringLiteral(" |\n\n");

    out << QStringLiteral("## Severity Distribution\n\n");
    out << QStringLiteral("| Severity | Count |\n");
    out << QStringLiteral("|----------|-------|\n");
    const QStringList severities = {QStringLiteral("Critical"), QStringLiteral("High"), QStringLiteral("Medium"), QStringLiteral("Low"), QStringLiteral("Info")};
    for (const QString &sev : severities) {
        out << QStringLiteral("| ") << sev << QStringLiteral(" | ") << QString::number(report.severityCounts.value(sev, 0)) << QStringLiteral(" |\n");
    }
    out << QStringLiteral("\n");

    out << QStringLiteral("## Vulnerabilities\n\n");
    int num = 0;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        ++num;
        out << QStringLiteral("### ") << QString::number(num) << QStringLiteral(". ") << vuln.title << QStringLiteral("\n\n");
        out << QStringLiteral("- **Severity:** ") << vuln.severity << QStringLiteral("\n");
        out << QStringLiteral("- **URL:** `") << vuln.url << QStringLiteral("`\n");
        if (!vuln.parameter.isEmpty()) {
            out << QStringLiteral("- **Parameter:** `") << vuln.parameter << QStringLiteral("`\n");
        }
        if (!vuln.cwe.isEmpty()) {
            out << QStringLiteral("- **CWE:** ") << vuln.cwe << QStringLiteral("\n");
        }
        out << QStringLiteral("\n**Description:** ") << vuln.description << QStringLiteral("\n\n");
        if (!vuln.payload.isEmpty()) {
            out << QStringLiteral("**Payload:**\n```\n") << vuln.payload << QStringLiteral("\n```\n\n");
        }
        if (!vuln.remediation.isEmpty()) {
            out << QStringLiteral("**Remediation:** ") << vuln.remediation << QStringLiteral("\n\n");
        }
        out << QStringLiteral("---\n\n");
    }

    return md;
}

QString ReportGenerator::generateCsvReport(const ScanReport &report) {
    QString csv;
    QTextStream out(&csv);

    out << QStringLiteral("ID,Title,Severity,URL,Parameter,CWE,CVSS,Description,Payload,Remediation,Discovered At\n");

    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        out << escapeCsv(vuln.id) << QStringLiteral(",");
        out << escapeCsv(vuln.title) << QStringLiteral(",");
        out << escapeCsv(vuln.severity) << QStringLiteral(",");
        out << escapeCsv(vuln.url) << QStringLiteral(",");
        out << escapeCsv(vuln.parameter) << QStringLiteral(",");
        out << escapeCsv(vuln.cwe) << QStringLiteral(",");
        out << escapeCsv(vuln.cvss) << QStringLiteral(",");
        out << escapeCsv(vuln.description) << QStringLiteral(",");
        out << escapeCsv(vuln.payload) << QStringLiteral(",");
        out << escapeCsv(vuln.remediation) << QStringLiteral(",");
        out << vuln.discoveredAt.toString(Qt::ISODate) << QStringLiteral("\n");
    }

    return csv;
}

QString ReportGenerator::generateTextReport(const ScanReport &report) {
    QString txt;
    QTextStream out(&txt);

    out << QString(QStringLiteral("=")).repeated(80) << QStringLiteral("\n");
    out << QStringLiteral("                    SECURITY SCAN REPORT\n");
    out << QString(QStringLiteral("=")).repeated(80) << QStringLiteral("\n\n");

    out << QStringLiteral("SCAN SUMMARY\n");
    out << QString(QStringLiteral("-")).repeated(40) << QStringLiteral("\n");
    out << QStringLiteral("Target URL:      ") << report.targetUrl << QStringLiteral("\n");
    out << QStringLiteral("Scan ID:         ") << report.scanId << QStringLiteral("\n");
    out << QStringLiteral("Start Time:      ") << report.startTime.toString(Qt::ISODate) << QStringLiteral("\n");
    out << QStringLiteral("End Time:        ") << report.endTime.toString(Qt::ISODate) << QStringLiteral("\n");
    out << QStringLiteral("Duration:        ") << QString::number(report.startTime.secsTo(report.endTime)) << QStringLiteral(" seconds\n");
    out << QStringLiteral("Total Requests:  ") << QString::number(report.totalRequests) << QStringLiteral("\n");
    out << QStringLiteral("Vulnerabilities: ") << QString::number(report.totalVulnerabilities) << QStringLiteral("\n\n");

    out << QStringLiteral("SEVERITY DISTRIBUTION\n");
    out << QString(QStringLiteral("-")).repeated(40) << QStringLiteral("\n");
    const QStringList severities = {QStringLiteral("Critical"), QStringLiteral("High"), QStringLiteral("Medium"), QStringLiteral("Low"), QStringLiteral("Info")};
    for (const QString &sev : severities) {
        out << QString(QStringLiteral("%1: %2\n")).arg(sev, -12).arg(report.severityCounts.value(sev, 0));
    }
    out << QStringLiteral("\n");

    out << QStringLiteral("VULNERABILITIES\n");
    out << QString(QStringLiteral("=")).repeated(80) << QStringLiteral("\n\n");

    int num = 0;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        ++num;
        out << QStringLiteral("[") << QString::number(num) << QStringLiteral("] ") << vuln.title << QStringLiteral("\n");
        out << QString(QStringLiteral("-")).repeated(60) << QStringLiteral("\n");
        out << QStringLiteral("Severity:    ") << vuln.severity << QStringLiteral("\n");
        out << QStringLiteral("URL:         ") << vuln.url << QStringLiteral("\n");
        if (!vuln.parameter.isEmpty()) {
            out << QStringLiteral("Parameter:   ") << vuln.parameter << QStringLiteral("\n");
        }
        if (!vuln.cwe.isEmpty()) {
            out << QStringLiteral("CWE:         ") << vuln.cwe << QStringLiteral("\n");
        }
        out << QStringLiteral("\nDescription:\n") << vuln.description << QStringLiteral("\n");
        if (!vuln.payload.isEmpty()) {
            out << QStringLiteral("\nPayload:\n") << vuln.payload << QStringLiteral("\n");
        }
        if (!vuln.remediation.isEmpty()) {
            out << QStringLiteral("\nRemediation:\n") << vuln.remediation << QStringLiteral("\n");
        }
        out << QStringLiteral("\n");
    }

    out << QString(QStringLiteral("=")).repeated(80) << QStringLiteral("\n");
    out << QStringLiteral("End of Report\n");

    return txt;
}

QString ReportGenerator::generatePdfReportContent(const ScanReport &report) {
    return generateHtmlReport(report);
}

QString ReportGenerator::generateExecutiveSummary(const ScanReport &report) {
    QString summary;
    QTextStream out(&summary);

    out << QStringLiteral("EXECUTIVE SUMMARY\n");
    out << QStringLiteral("=================\n\n");

    out << QStringLiteral("A security assessment was conducted on ") << report.targetUrl << QStringLiteral(" ");
    out << QStringLiteral("between ") << report.startTime.toString(QStringLiteral("MMMM d, yyyy")) << QStringLiteral(" ");
    out << QStringLiteral("and ") << report.endTime.toString(QStringLiteral("MMMM d, yyyy")) << QStringLiteral(".\n\n");

    int criticalCount = report.severityCounts.value(QStringLiteral("Critical"), 0);
    int highCount = report.severityCounts.value(QStringLiteral("High"), 0);
    int mediumCount = report.severityCounts.value(QStringLiteral("Medium"), 0);
    int lowCount = report.severityCounts.value(QStringLiteral("Low"), 0);

    out << QStringLiteral("KEY FINDINGS:\n");
    out << QStringLiteral("- Total vulnerabilities discovered: ") << QString::number(report.totalVulnerabilities) << QStringLiteral("\n");
    out << QStringLiteral("- Critical severity issues: ") << QString::number(criticalCount) << QStringLiteral("\n");
    out << QStringLiteral("- High severity issues: ") << QString::number(highCount) << QStringLiteral("\n");
    out << QStringLiteral("- Medium severity issues: ") << QString::number(mediumCount) << QStringLiteral("\n");
    out << QStringLiteral("- Low severity issues: ") << QString::number(lowCount) << QStringLiteral("\n\n");

    if (criticalCount > 0 || highCount > 0) {
        out << QStringLiteral("RISK ASSESSMENT: HIGH\n");
        out << QStringLiteral("Immediate action is recommended to address critical and high severity vulnerabilities.\n\n");
    } else if (mediumCount > 0) {
        out << QStringLiteral("RISK ASSESSMENT: MEDIUM\n");
        out << QStringLiteral("Action should be taken within the next sprint to address medium severity issues.\n\n");
    } else {
        out << QStringLiteral("RISK ASSESSMENT: LOW\n");
        out << QStringLiteral("Minor issues identified that should be addressed as part of regular maintenance.\n\n");
    }

    out << QStringLiteral("RECOMMENDATIONS:\n");
    out << QStringLiteral("1. Prioritize fixing critical and high severity vulnerabilities\n");
    out << QStringLiteral("2. Implement input validation and output encoding\n");
    out << QStringLiteral("3. Review and update security headers\n");
    out << QStringLiteral("4. Schedule regular security assessments\n");
    out << QStringLiteral("5. Implement a vulnerability management program\n");

    return summary;
}

QString ReportGenerator::generateTechnicalDetails(const ScanReport &report) {
    QString details;
    QTextStream out(&details);

    out << QStringLiteral("TECHNICAL DETAILS\n");
    out << QStringLiteral("=================\n\n");

    out << QStringLiteral("SCAN METHODOLOGY:\n");
    out << QStringLiteral("- Automated security scanning\n");
    out << QStringLiteral("- OWASP Top 10 vulnerability checks\n");
    out << QStringLiteral("- CWE Top 25 vulnerability checks\n");
    out << QStringLiteral("- Custom security rule verification\n\n");

    out << QStringLiteral("SCAN STATISTICS:\n");
    out << QStringLiteral("- Total HTTP requests sent: ") << QString::number(report.totalRequests) << QStringLiteral("\n");
    out << QStringLiteral("- Scan duration: ") << QString::number(report.startTime.secsTo(report.endTime)) << QStringLiteral(" seconds\n");
    out << QStringLiteral("- Average requests per second: ");
    qint64 duration = report.startTime.secsTo(report.endTime);
    if (duration > 0) {
        out << QString::number(static_cast<double>(report.totalRequests) / duration, 'f', 2);
    } else {
        out << QStringLiteral("N/A");
    }
    out << QStringLiteral("\n\n");

    out << QStringLiteral("VULNERABILITY CATEGORIES:\n");
    for (auto it = report.categoryCounts.constBegin(); it != report.categoryCounts.constEnd(); ++it) {
        out << QStringLiteral("- ") << it.key() << QStringLiteral(": ") << QString::number(it.value()) << QStringLiteral("\n");
    }

    return details;
}

QString ReportGenerator::generateRemediationPlan(const ScanReport &report) {
    QString plan;
    QTextStream out(&plan);

    out << QStringLiteral("REMEDIATION PLAN\n");
    out << QStringLiteral("================\n\n");

    out << QStringLiteral("PHASE 1: CRITICAL ISSUES (Immediate - within 24 hours)\n");
    out << QString(QStringLiteral("-")).repeated(50) << QStringLiteral("\n");
    int critCount = 0;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        if (vuln.severity == QStringLiteral("Critical")) {
            ++critCount;
            out << QString::number(critCount) << QStringLiteral(". ") << vuln.title << QStringLiteral("\n");
            out << QStringLiteral("   URL: ") << vuln.url << QStringLiteral("\n");
            out << QStringLiteral("   Fix: ") << vuln.remediation << QStringLiteral("\n\n");
        }
    }
    if (critCount == 0) out << QStringLiteral("No critical issues found.\n\n");

    out << QStringLiteral("PHASE 2: HIGH SEVERITY ISSUES (Within 1 week)\n");
    out << QString(QStringLiteral("-")).repeated(50) << QStringLiteral("\n");
    int highCount = 0;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        if (vuln.severity == QStringLiteral("High")) {
            ++highCount;
            out << QString::number(highCount) << QStringLiteral(". ") << vuln.title << QStringLiteral("\n");
            out << QStringLiteral("   URL: ") << vuln.url << QStringLiteral("\n");
            out << QStringLiteral("   Fix: ") << vuln.remediation << QStringLiteral("\n\n");
        }
    }
    if (highCount == 0) out << QStringLiteral("No high severity issues found.\n\n");

    out << QStringLiteral("PHASE 3: MEDIUM SEVERITY ISSUES (Within 1 month)\n");
    out << QString(QStringLiteral("-")).repeated(50) << QStringLiteral("\n");
    int medCount = 0;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        if (vuln.severity == QStringLiteral("Medium")) {
            ++medCount;
            out << QString::number(medCount) << QStringLiteral(". ") << vuln.title << QStringLiteral("\n");
        }
    }
    if (medCount == 0) out << QStringLiteral("No medium severity issues found.\n");
    out << QStringLiteral("\n");

    out << QStringLiteral("PHASE 4: LOW SEVERITY ISSUES (Within 3 months)\n");
    out << QString(QStringLiteral("-")).repeated(50) << QStringLiteral("\n");
    int lowCount = 0;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        if (vuln.severity == QStringLiteral("Low")) {
            ++lowCount;
        }
    }
    out << QString::number(lowCount) << QStringLiteral(" low severity issues to address.\n");

    return plan;
}

QJsonObject ReportGenerator::toJsonObject(const VulnerabilityReport &vuln) {
    QJsonObject obj;
    obj[QStringLiteral("id")] = vuln.id;
    obj[QStringLiteral("title")] = vuln.title;
    obj[QStringLiteral("severity")] = vuln.severity;
    obj[QStringLiteral("description")] = vuln.description;
    obj[QStringLiteral("url")] = vuln.url;
    obj[QStringLiteral("parameter")] = vuln.parameter;
    obj[QStringLiteral("payload")] = vuln.payload;
    obj[QStringLiteral("evidence")] = vuln.evidence;
    obj[QStringLiteral("remediation")] = vuln.remediation;
    obj[QStringLiteral("cvss")] = vuln.cvss;
    obj[QStringLiteral("cwe")] = vuln.cwe;
    obj[QStringLiteral("discoveredAt")] = vuln.discoveredAt.toString(Qt::ISODate);
    return obj;
}

QJsonObject ReportGenerator::toJsonObject(const ScanReport &report) {
    QJsonObject obj;
    obj[QStringLiteral("scanId")] = report.scanId;
    obj[QStringLiteral("targetUrl")] = report.targetUrl;
    obj[QStringLiteral("startTime")] = report.startTime.toString(Qt::ISODate);
    obj[QStringLiteral("endTime")] = report.endTime.toString(Qt::ISODate);
    obj[QStringLiteral("totalRequests")] = report.totalRequests;
    obj[QStringLiteral("totalVulnerabilities")] = report.totalVulnerabilities;

    QJsonObject severityCounts;
    for (auto it = report.severityCounts.constBegin(); it != report.severityCounts.constEnd(); ++it) {
        severityCounts[it.key()] = it.value();
    }
    obj[QStringLiteral("severityCounts")] = severityCounts;

    QJsonObject categoryCounts;
    for (auto it = report.categoryCounts.constBegin(); it != report.categoryCounts.constEnd(); ++it) {
        categoryCounts[it.key()] = it.value();
    }
    obj[QStringLiteral("categoryCounts")] = categoryCounts;

    QJsonArray vulns;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        vulns.append(toJsonObject(vuln));
    }
    obj[QStringLiteral("vulnerabilities")] = vulns;

    return obj;
}

QString ReportGenerator::severityToColor(const QString &severity) {
    if (severity == QStringLiteral("Critical")) return QStringLiteral("#dc3545");
    if (severity == QStringLiteral("High")) return QStringLiteral("#fd7e14");
    if (severity == QStringLiteral("Medium")) return QStringLiteral("#ffc107");
    if (severity == QStringLiteral("Low")) return QStringLiteral("#28a745");
    return QStringLiteral("#17a2b8");
}

QString ReportGenerator::severityToBadge(const QString &severity) {
    QString color = severityToColor(severity);
    return QString(QStringLiteral("<span class=\"badge\" style=\"background-color: %1;\">%2</span>")).arg(color, severity);
}

int ReportGenerator::severityToScore(const QString &severity) {
    if (severity == QStringLiteral("Critical")) return 10;
    if (severity == QStringLiteral("High")) return 8;
    if (severity == QStringLiteral("Medium")) return 5;
    if (severity == QStringLiteral("Low")) return 2;
    return 0;
}

QString ReportGenerator::getHtmlStyles() {
    QString css;
    css += QStringLiteral("<style>\n");
    css += QStringLiteral("* { box-sizing: border-box; margin: 0; padding: 0; }\n");
    css += QStringLiteral("body { font-family: -apple-system, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }\n");
    css += QStringLiteral(".container { max-width: 1200px; margin: 0 auto; padding: 20px; }\n");
    css += QStringLiteral("h1 { color: #1a1a2e; margin-bottom: 30px; font-size: 2.5em; }\n");
    css += QStringLiteral("h2 { color: #16213e; margin: 30px 0 20px; font-size: 1.8em; border-bottom: 2px solid #e94560; padding-bottom: 10px; }\n");
    css += QStringLiteral("h3 { color: #0f3460; font-size: 1.3em; }\n");
    css += QStringLiteral("h4 { color: #16213e; margin: 15px 0 10px; }\n");
    css += QStringLiteral(".summary-box { background: white; padding: 25px; border-radius: 10px; margin-bottom: 30px; }\n");
    css += QStringLiteral(".summary-table { width: 100%; border-collapse: collapse; }\n");
    css += QStringLiteral(".summary-table td { padding: 10px; border-bottom: 1px solid #eee; }\n");
    css += QStringLiteral(".severity-summary { margin-bottom: 30px; }\n");
    css += QStringLiteral(".severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; }\n");
    css += QStringLiteral(".severity-card { background: white; padding: 20px; border-radius: 10px; text-align: center; }\n");
    css += QStringLiteral(".severity-card.critical { border-left: 4px solid #dc3545; }\n");
    css += QStringLiteral(".severity-card.high { border-left: 4px solid #fd7e14; }\n");
    css += QStringLiteral(".severity-card.medium { border-left: 4px solid #ffc107; }\n");
    css += QStringLiteral(".severity-card.low { border-left: 4px solid #28a745; }\n");
    css += QStringLiteral(".severity-card.info { border-left: 4px solid #17a2b8; }\n");
    css += QStringLiteral(".severity-card .count { display: block; font-size: 2.5em; font-weight: bold; }\n");
    css += QStringLiteral(".severity-card .label { color: #666; font-size: 0.9em; text-transform: uppercase; }\n");
    css += QStringLiteral(".vuln-card { background: white; padding: 25px; border-radius: 10px; margin-bottom: 20px; }\n");
    css += QStringLiteral(".vuln-card.critical { border-left: 4px solid #dc3545; }\n");
    css += QStringLiteral(".vuln-card.high { border-left: 4px solid #fd7e14; }\n");
    css += QStringLiteral(".vuln-card.medium { border-left: 4px solid #ffc107; }\n");
    css += QStringLiteral(".vuln-card.low { border-left: 4px solid #28a745; }\n");
    css += QStringLiteral(".vuln-card.info { border-left: 4px solid #17a2b8; }\n");
    css += QStringLiteral(".vuln-header { display: flex; align-items: center; margin-bottom: 20px; }\n");
    css += QStringLiteral(".vuln-header h3 { flex: 1; margin: 0 15px; }\n");
    css += QStringLiteral(".vuln-num { background: #1a1a2e; color: white; width: 35px; height: 35px; border-radius: 50%; }\n");
    css += QStringLiteral(".badge { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }\n");
    css += QStringLiteral(".vuln-meta { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px; }\n");
    css += QStringLiteral(".vuln-meta p { margin: 0; }\n");
    css += QStringLiteral("code { background: #f1f1f1; padding: 2px 6px; border-radius: 4px; }\n");
    css += QStringLiteral("pre { background: #1a1a2e; color: #e0e0e0; padding: 15px; border-radius: 8px; overflow-x: auto; }\n");
    css += QStringLiteral("pre code { background: transparent; padding: 0; color: inherit; }\n");
    css += QStringLiteral(".vuln-description, .vuln-payload, .vuln-evidence, .vuln-remediation { margin-bottom: 15px; }\n");
    css += QStringLiteral("</style>\n");
    return css;
}

QString ReportGenerator::getHtmlHeader(const QString &title) {
    return QString(QStringLiteral("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>%1</title>\n")).arg(escapeHtml(title));
}

QString ReportGenerator::getHtmlFooter() {
    return QStringLiteral("</body>\n</html>\n");
}

QString ReportGenerator::escapeHtml(const QString &text) {
    QString escaped = text;
    escaped.replace(QChar('&'), QStringLiteral("&amp;"));
    escaped.replace(QChar('<'), QStringLiteral("&lt;"));
    escaped.replace(QChar('>'), QStringLiteral("&gt;"));
    escaped.replace(QChar('"'), QStringLiteral("&quot;"));
    escaped.replace(QChar('\''), QStringLiteral("&#39;"));
    return escaped;
}

QString ReportGenerator::escapeXml(const QString &text) {
    return escapeHtml(text);
}

QString ReportGenerator::escapeCsv(const QString &text) {
    if (text.contains(QChar(',')) || text.contains(QChar('"')) || text.contains(QChar('\n'))) {
        QString escaped = text;
        escaped.replace(QChar('"'), QStringLiteral("\"\""));
        return QStringLiteral("\"") + escaped + QStringLiteral("\"");
    }
    return text;
}

QStringList ReportGenerator::getReportTemplates() {
    return {
        QStringLiteral("default"),
        QStringLiteral("executive"),
        QStringLiteral("technical"),
        QStringLiteral("compliance"),
        QStringLiteral("minimal"),
    };
}

QString ReportGenerator::applyTemplate(const QString &templateName, const ScanReport &report) {
    if (templateName == QStringLiteral("executive")) {
        return generateExecutiveSummary(report);
    }
    if (templateName == QStringLiteral("technical")) {
        return generateTechnicalDetails(report);
    }
    if (templateName == QStringLiteral("minimal")) {
        return generateTextReport(report);
    }
    return generateHtmlReport(report);
}

QString ReportGenerator::generateOwaspTop10Summary(const ScanReport &report) {
    QString summary;
    QTextStream out(&summary);

    out << QStringLiteral("OWASP TOP 10 ANALYSIS\n");
    out << QStringLiteral("=====================\n\n");

    struct OwaspCategory {
        QString id;
        QString name;
        QStringList keywords;
    };

    QList<OwaspCategory> owaspCategories = {
        {QStringLiteral("A01"), QStringLiteral("Broken Access Control"), {QStringLiteral("IDOR"), QStringLiteral("access"), QStringLiteral("authorization")}},
        {QStringLiteral("A02"), QStringLiteral("Cryptographic Failures"), {QStringLiteral("crypto"), QStringLiteral("ssl"), QStringLiteral("tls"), QStringLiteral("encryption")}},
        {QStringLiteral("A03"), QStringLiteral("Injection"), {QStringLiteral("SQL"), QStringLiteral("injection"), QStringLiteral("command"), QStringLiteral("LDAP"), QStringLiteral("XPath")}},
        {QStringLiteral("A04"), QStringLiteral("Insecure Design"), {QStringLiteral("design"), QStringLiteral("logic")}},
        {QStringLiteral("A05"), QStringLiteral("Security Misconfiguration"), {QStringLiteral("config"), QStringLiteral("header"), QStringLiteral("disclosure")}},
        {QStringLiteral("A06"), QStringLiteral("Vulnerable Components"), {QStringLiteral("CVE"), QStringLiteral("outdated"), QStringLiteral("version")}},
        {QStringLiteral("A07"), QStringLiteral("Auth Failures"), {QStringLiteral("auth"), QStringLiteral("session"), QStringLiteral("credential")}},
        {QStringLiteral("A08"), QStringLiteral("Software and Data Integrity"), {QStringLiteral("integrity"), QStringLiteral("deserialization")}},
        {QStringLiteral("A09"), QStringLiteral("Security Logging and Monitoring"), {QStringLiteral("logging"), QStringLiteral("monitoring")}},
        {QStringLiteral("A10"), QStringLiteral("Server-Side Request Forgery"), {QStringLiteral("SSRF"), QStringLiteral("server-side")}},
    };

    for (const OwaspCategory &cat : owaspCategories) {
        int count = 0;
        for (const VulnerabilityReport &vuln : report.vulnerabilities) {
            for (const QString &keyword : cat.keywords) {
                if (vuln.title.contains(keyword, Qt::CaseInsensitive) ||
                    vuln.description.contains(keyword, Qt::CaseInsensitive)) {
                    ++count;
                    break;
                }
            }
        }
        out << cat.id << QStringLiteral(" - ") << cat.name << QStringLiteral(": ") << QString::number(count) << QStringLiteral(" findings\n");
    }

    return summary;
}

QString ReportGenerator::generateCweTop25Summary(const ScanReport &report) {
    QString summary;
    QTextStream out(&summary);

    out << QStringLiteral("CWE TOP 25 ANALYSIS\n");
    out << QStringLiteral("===================\n\n");

    QHash<QString, int> cweCounts;
    for (const VulnerabilityReport &vuln : report.vulnerabilities) {
        if (!vuln.cwe.isEmpty()) {
            cweCounts[vuln.cwe]++;
        }
    }

    QList<QPair<QString, int>> sorted;
    for (auto it = cweCounts.constBegin(); it != cweCounts.constEnd(); ++it) {
        sorted.append(qMakePair(it.key(), it.value()));
    }
    std::sort(sorted.begin(), sorted.end(), [](const QPair<QString, int> &a, const QPair<QString, int> &b) {
        return a.second > b.second;
    });

    for (const auto &pair : sorted) {
        out << pair.first << QStringLiteral(": ") << QString::number(pair.second) << QStringLiteral(" findings\n");
    }

    return summary;
}

QString ReportGenerator::generateComplianceReport(const ScanReport &report, const QString &standard) {
    QString compliance;
    QTextStream out(&compliance);

    out << QStringLiteral("COMPLIANCE REPORT: ") << standard.toUpper() << QStringLiteral("\n");
    out << QString(QStringLiteral("=")).repeated(40 + static_cast<int>(standard.length())) << QStringLiteral("\n\n");

    if (standard == QStringLiteral("PCI-DSS")) {
        out << QStringLiteral("PCI-DSS v4.0 Compliance Assessment\n\n");
        out << QStringLiteral("Requirement 6: Develop and Maintain Secure Systems\n");
        out << QString(QStringLiteral("-")).repeated(50) << QStringLiteral("\n");

        int sqlCount = 0, xssCount = 0;
        for (const VulnerabilityReport &vuln : report.vulnerabilities) {
            if (vuln.title.contains(QStringLiteral("SQL"), Qt::CaseInsensitive)) sqlCount++;
            if (vuln.title.contains(QStringLiteral("XSS"), Qt::CaseInsensitive)) xssCount++;
        }

        out << QStringLiteral("6.2.4 - SQL Injection Prevention: ");
        out << (sqlCount == 0 ? QStringLiteral("COMPLIANT") : QStringLiteral("NON-COMPLIANT")) << QStringLiteral("\n");
        out << QStringLiteral("6.2.4 - XSS Prevention: ");
        out << (xssCount == 0 ? QStringLiteral("COMPLIANT") : QStringLiteral("NON-COMPLIANT")) << QStringLiteral("\n");
    } else if (standard == QStringLiteral("HIPAA")) {
        out << QStringLiteral("HIPAA Security Rule Assessment\n\n");
        out << QStringLiteral("Technical Safeguards (164.312)\n");
        out << QString(QStringLiteral("-")).repeated(50) << QStringLiteral("\n");
        out << QStringLiteral("Access Controls: Review Required\n");
        out << QStringLiteral("Audit Controls: Review Required\n");
        out << QStringLiteral("Integrity Controls: Review Required\n");
        out << QStringLiteral("Transmission Security: Review Required\n");
    } else {
        out << QStringLiteral("Generic compliance assessment based on vulnerability findings.\n");
        out << QStringLiteral("Total findings: ") << QString::number(report.totalVulnerabilities) << QStringLiteral("\n");
    }

    return compliance;
}
