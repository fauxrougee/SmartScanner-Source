#include "clireport.h"
#include "issue.h"
#include "scanner.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QTextStream>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    Issue issue;
    issue.field00 = QStringLiteral("catalogue-1");
    issue.field18 = QStringLiteral("report-name");
    issue.field30 = QUrl(QStringLiteral("https://example.invalid/report"));
    issue.field38 = 2;
    issue.field40 = QStringLiteral("https://example.invalid/");
    issue.field58 = QStringLiteral("details");
    issue.field70 = QStringLiteral("queryName");
    issue.field88 = QStringLiteral("queryValue");
    issue.fieldA0 = 1;
    issue.fieldA8 = QStringLiteral("description");
    issue.fieldC0 = QStringLiteral("recommendation");
    issue.fieldD8.append({QStringLiteral("reference"), QStringLiteral("https://ref.invalid")});
    issue.fieldF0.append({QByteArrayLiteral("GET /"), QByteArrayLiteral("HTTP/1.1 200")});
    issue.field108.insert(QStringLiteral("custom"), {QStringLiteral("one"), QStringLiteral("two")});
    issue.field118.append(QStringLiteral("WASC-1"));

    const QJsonObject json = CliReport::issueJson(issue);
    if (json.value(QStringLiteral("dbId")) != QStringLiteral("catalogue-1")
        || json.value(QStringLiteral("impact")).toInt() != 2
        || json.value(QStringLiteral("parameter")).toObject()
               .value(QStringLiteral("type")) != QStringLiteral("Query")
        || json.value(QStringLiteral("http")).toArray().size() != 1
        || json.value(QStringLiteral("references")).toArray().size() != 1
        || json.value(QStringLiteral("classification")).toObject()
               .value(QStringLiteral("wasc")).toArray().size() != 1) {
        return 1;
    }

    Scanner scanner;
    scanner.issueDb().add(issue);
    QTemporaryDir directory;
    if (!directory.isValid())
        return 2;
    const QString path = directory.filePath(QStringLiteral("report.json"));
    QByteArray outBytes;
    QByteArray errorBytes;
    QBuffer outBuffer(&outBytes);
    QBuffer errorBuffer(&errorBytes);
    outBuffer.open(QIODevice::WriteOnly);
    errorBuffer.open(QIODevice::WriteOnly);
    QTextStream out(&outBuffer);
    QTextStream error(&errorBuffer);
    if (!CliReport::write(path, scanner, out, error))
        return 3;
    out.flush();
    error.flush();
    QFile report(path);
    if (!report.open(QIODevice::ReadOnly))
        return 4;
    const QJsonDocument document = QJsonDocument::fromJson(report.readAll());
    const QJsonObject reportObject = document.object();
    if (!document.isObject() || reportObject.value(QStringLiteral("version"))
                                  != QStringLiteral("3.0.0")
        || reportObject.value(QStringLiteral("issues")).toArray().size() != 1
        || outBytes != QByteArrayLiteral("Report Saved to ") + path.toUtf8() + '\n'
        || !errorBytes.isEmpty()) {
        return 5;
    }
    return 0;
}
