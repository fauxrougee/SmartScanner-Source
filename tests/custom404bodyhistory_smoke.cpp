#include "custom404bodyhistory.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    Custom404BodyHistory history;
    const QUrl url(QStringLiteral("https://example.test/long-path"));
    const QByteArray first = QByteArrayLiteral("page HTTPS://EXAMPLE.TEST/LONG-PATH result");
    const QByteArray equivalent = QByteArrayLiteral("page https://example.test/long-path result");
    const QByteArray distinct = QByteArrayLiteral("completely unrelated response content");

    history.retainIfDistinct(first, url);
    if (history.count() != 1 || !history.hasSimilar(equivalent, url))
        return 1;

    history.retainIfDistinct(equivalent, url);
    if (history.count() != 1 || history.hasSimilar(distinct, url))
        return 2;

    history.retainIfDistinct(distinct, url);
    return history.count() == 2 ? 0 : 3;
}
