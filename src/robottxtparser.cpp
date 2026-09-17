#include "robottxtparser.h"

#include "sitemaplocation.h"

namespace {

constexpr auto robotTxtPatternOptions = QRegularExpression::CaseInsensitiveOption
    | QRegularExpression::MultilineOption;

bool isAcceptedCapture(const QString &capture)
{
    // gui.exe:0x1400B6047 and 0x1400B64A8.
    return !capture.isEmpty() && !capture.contains(QLatin1Char('*'), Qt::CaseSensitive)
        && !capture.contains(QLatin1Char('$'), Qt::CaseSensitive);
}

} // namespace

const QRegularExpression &robotTxtResourceExpression()
{
    // gui.exe:0x1400B6B81.
    static const QRegularExpression expression(
        QStringLiteral("(?:noindex|(?:dis)?allow)\\s*:\\s*([^:]+?)$"), robotTxtPatternOptions);
    return expression;
}

const QRegularExpression &robotTxtSitemapExpression()
{
    // gui.exe:0x1400B6BB8.
    static const QRegularExpression expression(QStringLiteral("Sitemap\\s*:\\s*([^\\n]+?)$"),
                                                robotTxtPatternOptions);
    return expression;
}

QSet<QUrl> robotTxtResourceLocations(const QUrl &sourceUrl, const QString &responseBody)
{
    QSet<QUrl> locations;
    const QRegularExpressionMatchIterator matches = robotTxtResourceExpression().globalMatch(responseBody);
    for (QRegularExpressionMatchIterator iterator = matches; iterator.hasNext();) {
        const QString capture = iterator.next().captured(1).trimmed();
        if (isAcceptedCapture(capture))
            locations.insert(resolveSitemapLocation(sourceUrl, capture));
    }
    return locations;
}

QList<QUrl> robotTxtSitemapLocations(const QUrl &sourceUrl, const QString &responseBody)
{
    QList<QUrl> locations;
    const QRegularExpressionMatchIterator matches = robotTxtSitemapExpression().globalMatch(responseBody);
    for (QRegularExpressionMatchIterator iterator = matches; iterator.hasNext();) {
        const QString capture = iterator.next().captured(1).trimmed();
        if (isAcceptedCapture(capture))
            locations.append(resolveSitemapLocation(sourceUrl, capture));
    }
    return locations;
}
