#include "custom404probescheduler.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QStringList registrations{
        QStringLiteral("skip::9"), QStringLiteral("one::7"),
        QStringLiteral("two::7"), QStringLiteral("three::7"),
        QStringLiteral("four::7"), QStringLiteral("five::7"),
        QStringLiteral("also-skip::9")};
    const auto events = custom404ScheduleProbeEvents(
        registrations, 5, [](const QString &scope, quint64) {
            return scope != QStringLiteral("skip") && scope != QStringLiteral("also-skip");
        });
    if (events.size() != 5)
        return 1;
    for (int index = 0; index < events.size(); ++index) {
        if (events.at(index).id != 7
            || events.at(index).scope
                   != QStringList{QStringLiteral("one"), QStringLiteral("two"),
                                  QStringLiteral("three"), QStringLiteral("four"),
                                  QStringLiteral("five")}
                          .at(index)) {
            return 2;
        }
    }
    if (!custom404ScheduleProbeEvents(registrations, 6,
                                      [](const QString &, quint64) { return true; })
             .isEmpty()) {
        return 3;
    }
    return 0;
}
