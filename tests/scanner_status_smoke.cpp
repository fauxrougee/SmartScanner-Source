#include "scanner.h"
#include <QCoreApplication>
#include <QDebug>

// Expected ordering read from gui.exe:0x1400E90E0 and sms.exe:0x1400E38B0.
// Exercise the actual Scanner slots and IssueDb, not a duplicate state adapter.
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("scanner_status_smoke"));
    QStringList events;
    Scanner first;
    QObject::connect(&first, &Scanner::statusChanged, &app,
        [&](Scanner::ScanStatus status) { events.append(QString::number(status)); });
    QObject::connect(&first, &Scanner::finished, &app, [&] { events.append(QStringLiteral("finished")); });
    QObject::connect(&first.issueDb(), &IssueDb::newIssueAdded, &app,
        [&](const Issue &) { events.append(QStringLiteral("issue")); });
    first.checkFinished();
    if (!events.isEmpty()) return 1;
    first.start();
    first.start(); // No duplicate start while Scanning.
    if (events != QStringList{QStringLiteral("1")}) return 2;
    events.clear();
    Issue pending;
    pending.field30 = QUrl(QStringLiteral("https://example.invalid/pending"));
    first.issueDb().add(pending, true);
    first.checkFinished();
    const QStringList expected{QStringLiteral("issue"), QStringLiteral("finished"), QStringLiteral("2")};
    if (events != expected) {
        qCritical() << "Native provision/finished/status order mismatch:" << events;
        return 3;
    }
    events.clear();
    first.checkFinished();
    if (!events.isEmpty()) return 4;

    Scanner second;
    QObject::connect(&second, &Scanner::statusChanged, &app,
        [&](Scanner::ScanStatus status) { events.append(QString::number(status)); });
    QObject::connect(&second, &Scanner::finished, &app, [&] { events.append(QStringLiteral("finished")); });
    second.start();
    second.pause();
    second.checkFinished();
    second.resume();
    second.stop();
    second.checkFinished();
    const QStringList cycle{QStringLiteral("1"), QStringLiteral("5"), QStringLiteral("6"),
        QStringLiteral("1"), QStringLiteral("3"), QStringLiteral("finished"), QStringLiteral("4")};
    if (events != cycle) {
        qCritical() << "Pause/resume/stop trace mismatch:" << events;
        return 5;
    }
    return 0;
}
