#include "manipulatorrouting.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QUrl queryUrl(QStringLiteral("https://example.test/path?a=1"));
    const QUrl plainUrl(QStringLiteral("https://example.test/path"));
    const ManipulatorRoutingPlan all = manipulatorRoutingPlan(true, 0x1f, queryUrl);
    if (!all.urlEncodedParameters || !all.flag2Engine || !all.flag4Engine
        || !all.flag8Engine || !all.flag16Engine)
        return 1;

    const ManipulatorRoutingPlan noQuery = manipulatorRoutingPlan(true, 0x1f, plainUrl);
    if (noQuery.urlEncodedParameters || !noQuery.flag2Engine || !noQuery.flag4Engine
        || !noQuery.flag8Engine || !noQuery.flag16Engine)
        return 2;

    const ManipulatorRoutingPlan absent = manipulatorRoutingPlan(false, 0x1f, queryUrl);
    return !absent.urlEncodedParameters && !absent.flag2Engine && !absent.flag4Engine
               && !absent.flag8Engine && !absent.flag16Engine
           ? 0
           : 3;
}
