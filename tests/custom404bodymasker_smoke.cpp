#include "custom404bodymasker.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QUrl url(QStringLiteral("https://example.test/long-path"));
    const QByteArray masked = custom404MaskedBody(
        QByteArrayLiteral("before HTTPS://EXAMPLE.TEST/LONG-PATH; example.test; /LONG-PATH; untouched"),
        url);
    if (masked != QByteArrayLiteral("before ; ; ; untouched"))
        return 1;
    if (!custom404MaskedBody({}, url).isEmpty())
        return 2;
    return 0;
}
