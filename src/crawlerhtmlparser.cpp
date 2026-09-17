#include "crawlerhtmlparser.h"

#include "crawlerparsehelpers.h"
#include "sitemaplocation.h"
#include "sitemapxmlparser.h"

namespace {
constexpr auto crawlerPatternOptions = QRegularExpression::CaseInsensitiveOption;

QList<QUrl> locationsFromExpression(const QUrl &baseUrl, const QString &document,
                                    const QRegularExpression &expression, bool applyFilter)
{
    QList<QUrl> locations;
    const QRegularExpressionMatchIterator matches = expression.globalMatch(document);
    for (QRegularExpressionMatchIterator iterator = matches; iterator.hasNext();) {
        const QUrl location = resolveSitemapLocation(baseUrl, crawlerAttributeCapture(iterator.next()));
        if (!applyFilter || crawlerAcceptsResolvedLocation(location))
            locations.append(location);
    }
    return locations;
}

QString withoutCrawlerScriptBlocks(QString document)
{
    // gui.exe:0x1400719B5 through 0x1400719E2.
    return document.replace(crawlerScriptExpression(), QStringLiteral("\n"));
}
}

const QRegularExpression &crawlerHrefExpression()
{
    static const QRegularExpression expression(
        QStringLiteral("\\bhref\\s*=\\s*(?(?=[\"'])(['\"])([\\s\\S]*?)\\1|([^\\s>]+))"),
        crawlerPatternOptions);
    return expression;
}

const QRegularExpression &crawlerSourceExpression()
{
    static const QRegularExpression expression(
        QStringLiteral("\\bsrc\\s*=\\s*(?(?=[\"'])(['\"])([\\s\\S]*?)\\1|([^\\s>]+))"),
        crawlerPatternOptions);
    return expression;
}

const QRegularExpression &crawlerIframeExpression()
{
    static const QRegularExpression expression(
        QStringLiteral("<iframe\\s+[^>]*?\\bsrc\\s*=\\s*(?(?=[\"'])(['\"])([\\s\\S]*?)\\1|([^\\s>]+))"),
        crawlerPatternOptions);
    return expression;
}

const QRegularExpression &crawlerScriptExpression()
{
    static const QRegularExpression expression(QStringLiteral("<script[\\s\\S]+?</script>"),
                                                crawlerPatternOptions);
    return expression;
}

const QRegularExpression &crawlerMetaRefreshExpression()
{
    static const QRegularExpression expression(
        QStringLiteral("<META\\s+[^>]*HTTP-EQUIV\\s*=\\s*['|\"]*REFRESH['|\"]*\\s+[^>]*URL\\s*=\\s*[\"|']*([^>\\s'\"]+)"),
        crawlerPatternOptions);
    return expression;
}

bool crawlerAcceptsContentType(const QByteArray &contentType)
{
    // gui.exe:0x14006E3D4-0x14006E5D4. The response handler locates the
    // exact-case `Content-Type` header twice. If it is absent it continues;
    // otherwise it lowercases its bytes and permits text except JavaScript.
    if (contentType.isNull())
        return true;
    const QByteArray lowered = contentType.toLower();
    return lowered.startsWith(QByteArrayLiteral("text"))
        && !lowered.contains(QByteArrayLiteral("javascript"));
}

QList<QUrl> crawlerHtmlHrefLocations(const QUrl &requestUrl, const QString &document)
{
    // gui.exe:0x140071B2E through 0x140071C04.
    return locationsFromExpression(crawlerDocumentBaseUrl(requestUrl, document),
                                   withoutCrawlerScriptBlocks(document), crawlerHrefExpression(), true);
}

QList<QUrl> crawlerHtmlIframeLocations(const QUrl &requestUrl, const QString &document)
{
    // gui.exe:0x140071EE6 through 0x140071FA6. Unlike href/src, native code
    // does not call 0x14006DA40 in this branch.
    return locationsFromExpression(crawlerDocumentBaseUrl(requestUrl, document), document,
                                   crawlerIframeExpression(), false);
}

QList<QUrl> crawlerHtmlSourceLocations(const QUrl &requestUrl, const QString &document)
{
    // gui.exe:0x1400721F5 through 0x1400722C2.
    return locationsFromExpression(crawlerDocumentBaseUrl(requestUrl, document),
                                   withoutCrawlerScriptBlocks(document), crawlerSourceExpression(), true);
}

QList<QUrl> crawlerMetaRefreshLocations(const QUrl &requestUrl, const QString &document)
{
    QList<QUrl> locations;
    const QRegularExpressionMatch match = crawlerMetaRefreshExpression().match(document);
    if (match.hasMatch())
        locations.append(resolveSitemapLocation(crawlerDocumentBaseUrl(requestUrl, document),
                                                match.captured(1)));
    return locations;
}
