#include "sitemapxmlparser.h"

#include "sitemaplocation.h"

namespace {
constexpr auto crawlerPatternOptions = QRegularExpression::CaseInsensitiveOption;
}

const QRegularExpression &crawlerXmlSitemapLocationExpression()
{
    static const QRegularExpression expression(
        QStringLiteral("<loc>(?:<!\\[CDATA\\[)?([\\s\\S]+?)(?:\\]\\]>)?<\\/loc>"),
        crawlerPatternOptions);
    return expression;
}

const QRegularExpression &crawlerRejectedLocationExpression()
{
    static const QRegularExpression expression(
        QStringLiteral("'|\"|<|>|;|\\.\\.|%0|passwd|web\\.conf|win\\.ini|md5\\(122459\\)|BENCHMARK\\(|or 1|or \\("),
        crawlerPatternOptions);
    return expression;
}

bool crawlerAcceptsResolvedLocation(const QUrl &location)
{
    const QString rendered = location.toString();
    // gui.exe:0x14006DA40. startsWith uses Qt::CaseSensitive (zero) here.
    return !rendered.startsWith(QStringLiteral("javascript:"), Qt::CaseSensitive)
        && !rendered.startsWith(QStringLiteral("mailto:"), Qt::CaseSensitive)
        && !rendered.startsWith(QStringLiteral("data:"), Qt::CaseSensitive)
        && !rendered.contains(crawlerRejectedLocationExpression());
}

QList<QUrl> crawlerXmlSitemapLocations(const QUrl &sourceUrl, const QString &contentType,
                                        const QString &responseBody)
{
    QList<QUrl> locations;
    // gui.exe:0x140071D34. QString::indexOf("xml") uses Qt::CaseSensitive.
    if (!contentType.contains(QStringLiteral("xml"), Qt::CaseSensitive))
        return locations;

    const QRegularExpressionMatchIterator matches
        = crawlerXmlSitemapLocationExpression().globalMatch(responseBody);
    for (QRegularExpressionMatchIterator iterator = matches; iterator.hasNext();) {
        const QUrl location = resolveSitemapLocation(sourceUrl, iterator.next().captured(1));
        if (crawlerAcceptsResolvedLocation(location))
            locations.append(location);
    }
    return locations;
}
