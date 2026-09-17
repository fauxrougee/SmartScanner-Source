#include "custom404probethresholds.h"

#include "custom404urlscope.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QUrl expected(QStringLiteral("https://Example.test/one/item.php"));
    const QUrl candidate(QStringLiteral("https://example.test/one/other.php"));
    const QString root = custom404PathRoot(candidate, custom404PathSlashCount(candidate));
    if (!custom404ProbeMatchesPathRoot(candidate.toString(), root))
        return 1;
    if (!custom404ProbeMatchesHost(QStringLiteral("https://EXAMPLE.TEST/other"), expected)
        || custom404ProbeMatchesHost(QStringLiteral("https://other.test/other"), expected)) {
        return 2;
    }
    return custom404ProbeMatchesUnconditionally() ? 0 : 3;
}
