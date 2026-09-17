#include "custom404probeplan.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QUrl url(QStringLiteral("https://example.test/one/item.php"));
    const QString registration = custom404ProbeRegistration(url, 42);
    if (!registration.endsWith(QStringLiteral("::42")))
        return 1;

    QStringList registrations;
    for (int index = 0; index < 15; ++index)
        registrations.append(QStringLiteral("https://example.test/one/%1::7").arg(index));
    const auto events = custom404ScheduleProbePlan(registrations, url);
    int atFive = 0;
    int atTen = 0;
    int atFifteen = 0;
    for (const Custom404ScheduledProbeEvent &event : events) {
        if (event.event.id != 7)
            return 2;
        if (event.threshold == 5)
            ++atFive;
        else if (event.threshold == 10)
            ++atTen;
        else if (event.threshold == 15)
            ++atFifteen;
        else
            return 3;
    }
    return atFive == 15 && atTen == 15 && atFifteen == 15 ? 0 : 4;
}
