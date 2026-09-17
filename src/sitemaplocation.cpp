#include "sitemaplocation.h"

#include "htmlnumericentity.h"

QUrl resolveDecodedSitemapLocation(const QUrl &base, QString decodedLocation)
{
    // gui.exe:0x140150490. The native trims after entity decoding. It changes
    // backslashes only in the path portion, preserving text from '?' onward.
    decodedLocation = decodedLocation.trimmed();
    const qsizetype queryOffset = decodedLocation.indexOf(QLatin1Char('?'));
    if (queryOffset < 0) {
        decodedLocation.replace(QLatin1Char('\\'), QLatin1Char('/'));
    } else {
        QString path = decodedLocation.left(queryOffset);
        path.replace(QLatin1Char('\\'), QLatin1Char('/'));
        decodedLocation = path + decodedLocation.mid(queryOffset);
    }
    return base.resolved(QUrl(decodedLocation));
}

QUrl resolveSitemapLocation(const QUrl &base, QString location)
{
    return resolveDecodedSitemapLocation(base, decodeHtmlCharacterReferences(std::move(location)));
}
