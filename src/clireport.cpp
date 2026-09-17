#include "clireport.h"

#include "issue.h"
#include "scanner.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTextStream>

namespace {

QString parameterType(qint32 type)
{
    // sms.exe:0x140024610.
    switch (type) {
    case 1: return QStringLiteral("Query");
    case 2: return QStringLiteral("Post");
    case 4: return QStringLiteral("Cookie");
    case 8: return QStringLiteral("Header");
    case 16: return QStringLiteral("Path");
    case 31: return QStringLiteral("status");
    default: return {};
    }
}

QString statusName(Scanner::ScanStatus status)
{
    // sms.exe:0x1400E4A90.
    switch (status) {
    case Scanner::Idle: return QStringLiteral("idle");
    case Scanner::Scanning: return QStringLiteral("inprogress");
    case Scanner::Finished: return QStringLiteral("finished");
    case Scanner::Stopping: return QStringLiteral("stopping");
    case Scanner::Stopped: return QStringLiteral("stopped");
    case Scanner::Pausing: return QStringLiteral("pausing");
    case Scanner::Paused: return QStringLiteral("paused");
    }
    return QStringLiteral("unknown");
}

QJsonObject classificationJson(const Issue &issue)
{
    // Final block of sms.exe:0x1400228D0. The classification object is always
    // present, while each list is emitted only when non-empty.
    QJsonObject result;
    const auto insertIfPresent = [&result](const QString &key,
                                            const QList<QString> &values) {
        if (!values.isEmpty())
            result.insert(key, QJsonArray::fromStringList(values));
    };
    insertIfPresent(QStringLiteral("wasc"), issue.field118);
    insertIfPresent(QStringLiteral("cvss3"), issue.field130);
    insertIfPresent(QStringLiteral("cvss4"), issue.field148);
    insertIfPresent(QStringLiteral("cve"), issue.field160);
    insertIfPresent(QStringLiteral("edb"), issue.field178);
    insertIfPresent(QStringLiteral("ghsa"), issue.field190);
    insertIfPresent(QStringLiteral("cwe"), issue.field1A8);
    insertIfPresent(QStringLiteral("owasp"), issue.field1C0);
    insertIfPresent(QStringLiteral("capec"), issue.field1D8);
    insertIfPresent(QStringLiteral("iso27001"), issue.field1F0);
    insertIfPresent(QStringLiteral("hipaa"), issue.field208);
    insertIfPresent(QStringLiteral("pcidss"), issue.field220);
    return result;
}

} // namespace

namespace CliReport {

QJsonObject issueJson(Issue issue)
{
    // Direct field/key transcription of sms.exe:0x1400228D0.
    QJsonObject result{
        {QStringLiteral("id"), static_cast<qint64>(issue.identity())},
        {QStringLiteral("name"), issue.field18},
        {QStringLiteral("url"), issue.field30.toString()},
        {QStringLiteral("impact"), issue.field38},
        {QStringLiteral("restriction"), issue.field110},
    };
    if (!issue.field00.isNull())
        result.insert(QStringLiteral("dbId"), issue.field00);
    if (!issue.field58.isNull())
        result.insert(QStringLiteral("details"), issue.field58);
    if (!issue.fieldC0.isNull())
        result.insert(QStringLiteral("recommendation"), issue.fieldC0);
    if (!issue.field40.isNull())
        result.insert(QStringLiteral("referer"), issue.field40);
    if (!issue.fieldA8.isNull())
        result.insert(QStringLiteral("description"), issue.fieldA8);

    if (!issue.field108.isEmpty()) {
        QJsonArray customFields;
        for (const QString &key : issue.field108.keys()) {
            QJsonArray values;
            for (const QString &value : issue.field108.value(key))
                values.append(value);
            customFields.append(QJsonObject{{QStringLiteral("key"), key},
                                             {QStringLiteral("values"), values}});
        }
        result.insert(QStringLiteral("customFields"), customFields);
    }
    if (issue.fieldA0 != 0) {
        result.insert(QStringLiteral("parameter"), QJsonObject{
            {QStringLiteral("name"), issue.field70},
            {QStringLiteral("value"), issue.field88},
            {QStringLiteral("type"), parameterType(issue.fieldA0)},
        });
    }
    if (!issue.fieldF0.isEmpty()) {
        QJsonArray http;
        for (const auto &[request, response] : issue.fieldF0) {
            http.append(QJsonObject{{QStringLiteral("request"), QString(request)},
                                    {QStringLiteral("response"), QString(response)}});
        }
        result.insert(QStringLiteral("http"), http);
    }
    if (!issue.fieldD8.isEmpty()) {
        QJsonArray references;
        for (const auto &[title, url] : issue.fieldD8) {
            references.append(QJsonObject{{QStringLiteral("title"), title},
                                          {QStringLiteral("url"), url}});
        }
        result.insert(QStringLiteral("references"), references);
    }
    result.insert(QStringLiteral("classification"), classificationJson(issue));
    return result;
}

bool write(const QString &path, const Scanner &scanner, QTextStream &standardOut,
           QTextStream &standardError)
{
    // sms.exe:0x140021490 uses WriteOnly | Truncate (0x12), emits the report
    // in QJsonDocument::Indented form, and does not create parent folders.
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        standardError << QStringLiteral("Could not open output file") << Qt::endl;
        return false;
    }

    QJsonArray issues;
    for (const Issue &issue : scanner.issueDb().issues())
        issues.append(issueJson(issue));
    const QJsonObject report{
        {QStringLiteral("target"), scanner.reportTarget()},
        {QStringLiteral("date"), scanner.startedDate().toString()},
        {QStringLiteral("status"), statusName(scanner.status())},
        {QStringLiteral("duration"), scanner.duration().toDisplayString()},
        {QStringLiteral("requests"), scanner.updateValues()
                                        .value(QStringLiteral("request_total")).toLongLong()},
        {QStringLiteral("version"), QStringLiteral("3.0.0")},
        {QStringLiteral("issues"), issues},
    };
    file.write(QJsonDocument(report).toJson(QJsonDocument::Indented));
    file.close();
    standardOut << QStringLiteral("Report Saved to %1").arg(path) << Qt::endl;
    return true;
}

} // namespace CliReport
