#pragma once

#include <QJsonObject>
#include <QString>

class Issue;
class Scanner;
class QTextStream;

namespace CliReport {

// sms.exe:0x1400228D0.
QJsonObject issueJson(Issue issue);

// sms.exe:0x140021490. Returns false only when QFile::open(WriteOnly |
// Truncate) fails; the native caller still finishes with its normal status.
bool write(const QString &path, const Scanner &scanner, QTextStream &standardOut,
           QTextStream &standardError);

} // namespace CliReport
