#include "issuedbdata.h"

#include <QCoreApplication>
#include <QDebug>

int main(int argc, char *argv[]) {
    QCoreApplication application(argc, argv);
    if (application.arguments().size() != 2) return 64;

    QJsonObject catalogue;
    QString error;
    if (!IssueDbData::loadJson(application.arguments().at(1), &catalogue, &error)) {
        qCritical().noquote() << error;
        return 1;
    }
    if (catalogue.isEmpty()) return 2;

    qInfo() << "Loaded issue entries:" << catalogue.size();
    return 0;
}
