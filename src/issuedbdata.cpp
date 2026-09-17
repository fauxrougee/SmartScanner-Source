#include "issuedbdata.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLoggingCategory>
#include <QMutex>
#include <QMutexLocker>

Q_LOGGING_CATEGORY(issueDbLog, "scanner.issueDb")

bool IssueDbData::loadJson(const QString &path, QJsonObject *result, QString *error) {
    if (!result) return false;

    // gui.exe:0x1400493D0 guards one process-wide cached object. It retries
    // loading only while that object is empty.
    static QMutex mutex;
    static QJsonObject cached;
    const QMutexLocker lock(&mutex);

    if (cached.isEmpty()) {
        QFile input(path);
        if (!input.open(QIODevice::ReadOnly)) {
            const auto message = input.errorString();
            qCWarning(issueDbLog) << "Failed to open database file:" << path
                                  << ": Error:" << message;
            if (error) *error = message;
            return false;
        }

        QJsonParseError parseError;
        const auto document = QJsonDocument::fromJson(input.readAll(), &parseError);
        if (parseError.error != QJsonParseError::NoError) {
            const auto message = parseError.errorString();
            qCWarning(issueDbLog) << "Failed to parse database file:" << path
                                  << ": Error:" << message << ':'
                                  << static_cast<int>(parseError.error);
            if (error) *error = message;
            return false;
        }
        cached = document.object();
    }

    *result = cached;
    if (error) error->clear();
    return true;
}
