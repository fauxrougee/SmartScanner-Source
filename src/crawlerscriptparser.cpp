#include "crawlerscriptparser.h"

#include "crawlerparsehelpers.h"
#include "sitemaplocation.h"
#include "sitemapxmlparser.h"

#include <QCryptographicHash>

namespace {

constexpr auto crawlerScriptPatternOptions = QRegularExpression::CaseInsensitiveOption;

} // namespace

const QRegularExpression &crawlerScriptElementExpression()
{
    // gui.exe:0x1400718F0 (lazy static at 0x1403611C8).
    static const QRegularExpression expression(
        QStringLiteral(R"(<script\b([^>]*)>([\s\S]*?)</script>)"),
        crawlerScriptPatternOptions);
    return expression;
}

const QRegularExpression &crawlerAnalyticsScriptExpression()
{
    // gui.exe:0x1400718F0 (lazy static at 0x1403611D8).
    static const QRegularExpression expression(QStringLiteral(
        R"(\b(?:google-analytics\.com|googletagmanager\.com|googletagservices\.com|gtag\/js|analytics\.js|ga\.js|_gaq|dataLayer\b|googlesitekit|doubleclick\.net|adsbygoogle|pagead\/conversion|conversion_async|clarity\b|clarity\.ms|connect\.facebook\.net|fbq\(|facebook-pixel|piwik\.js|piwik\.php|matomo\.js|matomo\.php|browser-insights\.cloudflare\.com|linkedin\.com\/insight|hotjar(?:\.com|\.js|\.static)|static\.hotjar|hj\(|omtrdc\.net|2o7\.net|adobedc\.com|omniture|s\.t\(|s\.tl\(|quantserve\.com|crazyegg\.com|segment\.com|fullstory\.com|mixpanel\.com|kissmetrics\.com|chartbeat\.com)\b)"),
        crawlerScriptPatternOptions);
    return expression;
}

const QRegularExpression &crawlerScriptTypeExpression()
{
    // gui.exe:0x1400718F0 (lazy static at 0x1403611E8).
    static const QRegularExpression expression(
        QStringLiteral(R"(\btype\s*=\s*(?:(?=["'])(['"])([\s\S]*?)\1|([^\s>]+)))"),
        crawlerScriptPatternOptions);
    return expression;
}

const QRegularExpression &crawlerScriptSourceExpression()
{
    // gui.exe:0x1400718F0 (lazy static at 0x1403611F8).
    static const QRegularExpression expression(
        QStringLiteral(R"(\bsrc\s*=\s*(?:(?=["'])(['"])([\s\S]*?)\1|([^\s>]+)))"),
        crawlerScriptPatternOptions);
    return expression;
}

const QRegularExpression &crawlerScriptEventExpression()
{
    // gui.exe:0x14006C89C-0x14006C8B4.
    static const QRegularExpression expression(QStringLiteral(
        R"(\bon(?:abort|auxclick|beforeunload|blur|change|click|close|contextmenu|dblclick|error|focus|formdata|input|invalid|load|loadeddata|loadedmetadata|loadstart|progress|ratechange|rejectionhandled|reset|stalled|storage|submit|toggle|unhandledrejection|unload|waiting)\s*=\s*(?:[^><]+)|\bjavascript:(?:[^><]+))"),
        crawlerScriptPatternOptions);
    return expression;
}

CrawlerScriptParseResult crawlerParseScripts(const QUrl &responseUrl, const QString &document)
{
    // gui.exe:0x1400718F0. The hash is SHA-1 (native constructor algorithm 1)
    // and receives accepted URLs with query/fragment removed, otherwise inline script
    // bodies, followed by every event/javascript-expression match.
    CrawlerScriptParseResult result;
    // gui.exe:0x140071947..0x14007198C constructs v91 from <base href>;
    // the script-source branch resolves against that same QUrl at 0x1400725FE.
    const QUrl documentBase = crawlerDocumentBaseUrl(responseUrl, document);
    QCryptographicHash hash(QCryptographicHash::Sha1);
    QRegularExpressionMatchIterator elements = crawlerScriptElementExpression().globalMatch(document);
    while (elements.hasNext()) {
        const QRegularExpressionMatch element = elements.next();
        if (crawlerAnalyticsScriptExpression().match(element.captured(1)).hasMatch())
            continue;

        const QString type = crawlerAttributeCapture(
            crawlerScriptTypeExpression().match(element.captured(0)));
        // gui.exe:0x140072452 tests QString length, not nullness. Both
        // value comparisons at 0x140072491/0x1400724E3 use CaseSensitive (1).
        if (!type.isEmpty() && type.compare(QStringLiteral("module"), Qt::CaseSensitive) != 0
            && type.compare(QStringLiteral("text/javascript"), Qt::CaseSensitive) != 0) {
            continue;
        }

        const QString source = crawlerAttributeCapture(
            crawlerScriptSourceExpression().match(element.captured(0)));
        // gui.exe:0x140072555 tests the source QString length (v119).
        if (source.isEmpty()) {
            hash.addData(element.captured(2).toUtf8());
            continue;
        }

        const QUrl location = resolveSitemapLocation(documentBase, source);
        if (!crawlerAcceptsResolvedLocation(location))
            continue;
        // The native QUrl::toString call uses formatting value 0xc0:
        // RemoveQuery | RemoveFragment, with the default decoded components.
        hash.addData(location.toString(QUrl::RemoveQuery | QUrl::RemoveFragment).toUtf8());
        result.sourceLocations.append(location);
    }

    QRegularExpressionMatchIterator events = crawlerScriptEventExpression().globalMatch(document);
    while (events.hasNext())
        hash.addData(events.next().captured(0).toUtf8());
    result.fingerprint = hash.result().toHex();
    return result;
}
