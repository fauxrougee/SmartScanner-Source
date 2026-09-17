#include "custom404urlhistory.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    Custom404UrlHistory history;
    const QUrl first(QStringLiteral("http://www.example.test/index.html"));
    const QUrl canonicalDuplicate(QStringLiteral("http://example.test/"));
    const QUrl second(QStringLiteral("https://another.test/path"));

    if (!history.accepts(first, 4) || history.urlCount(4) != 1)
        return 1;

    // Flag 14 removes www. and the default document, so the native loop
    // accepts this duplicate without appending it.
    if (!history.accepts(canonicalDuplicate, 4) || history.urlCount(4) != 1)
        return 2;

    // The integer argument selects a separate history sequence.
    if (!history.accepts(second, 9) || history.urlCount(9) != 1
        || history.urlCount(4) != 1) {
        return 3;
    }

    return 0;
}
