#ifndef HTTPHEADERANALYZER_H
#define HTTPHEADERANALYZER_H

#include <QString>
#include <QStringList>
#include <QMap>
#include <QList>

class HttpHeaderAnalyzer
{
public:
    enum class Severity {
        Info,
        Low,
        Medium,
        High,
        Critical
    };
    struct Finding {
        QString header;
        QString issue;
        QString recommendation;
        Severity severity;
    };

    HttpHeaderAnalyzer() = default;
    ~HttpHeaderAnalyzer() = default;

    QList<Finding> analyze(const QMap<QString, QString> &headers) const;
    bool hasSecurityIssues(const QMap<QString, QString> &headers) const;

    static QStringList getSecurityHeaders();
    static QStringList getInformationLeakageHeaders();
    static QStringList getCachingHeaders();
    static QString severityName(Severity sev);
};

#endif // HTTPHEADERANALYZER_H
