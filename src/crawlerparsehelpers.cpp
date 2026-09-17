#include "crawlerparsehelpers.h"

#include "httprequestrawpacket.h"
#include "sitemaplocation.h"

#include <QDomDocument>
#include <QVariant>

QString crawlerAttributeCapture(const QRegularExpressionMatch &match)
{
    if (!match.hasMatch())
        return {};

    const QString quoted = match.captured(2);
    return quoted.isNull() ? match.captured(3) : quoted;
}

QString crawlerFirstElementAttribute(const QString &document, const QString &element,
                                    const QString &attribute)
{
    // gui.exe:0x1401374ED through 0x1401375BC.
    const QString pattern = QStringLiteral("<") + element + QStringLiteral("\\s+[^>]*?\\b")
        + QRegularExpression::escape(attribute)
        + QStringLiteral("\\s*=\\s*(?(?=[\"'])(['\"])([\\s\\S]*?)\\1|([^\\s>]+))");
    const QRegularExpression expression(pattern, QRegularExpression::CaseInsensitiveOption);
    return crawlerAttributeCapture(expression.match(document));
}

QUrl crawlerDocumentBaseUrl(const QUrl &requestUrl, const QString &document)
{
    return resolveSitemapLocation(requestUrl,
                                  crawlerFirstElementAttribute(document, QStringLiteral("base"),
                                                               QStringLiteral("href")));
}

QString crawlerFirstElementAttributeOrFallback(const QString &document, const QString &element,
                                               const QString &attribute, const QString &fallback)
{
    // gui.exe:0x1400EDCAF through 0x1400EE41B.
    QDomDocument dom;
    dom.setContent(document);
    const QDomNodeList elements = dom.elementsByTagName(element);
    if (elements.length() > 0) {
        const QString domValue = elements.at(0).attributes().namedItem(attribute).nodeValue();
        if (!domValue.isNull())
            return domValue;
    }

    // The attribute text is appended verbatim in the native expressions.
    const QString prefix = QStringLiteral("\\b") + attribute;
    QRegularExpression expression(prefix + QStringLiteral("\\s*=\\s*\"([^\"]+)\""),
                                  QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch match = expression.match(document);
    if (match.hasMatch())
        return match.captured(1);

    expression.setPattern(prefix + QStringLiteral("\\s*=\\s*'([^']+)'"));
    match = expression.match(document);
    if (match.hasMatch())
        return match.captured(1);

    expression.setPattern(prefix + QStringLiteral("\\s*=\\s*([^\\s>]+)"));
    match = expression.match(document);
    if (match.hasMatch()) {
        const QString candidate = match.captured(1).trimmed();
        if (candidate != QStringLiteral("\"\"") && candidate != QStringLiteral("''"))
            return candidate;
        return fallback;
    }

    expression.setPattern(prefix + QStringLiteral("\\b"));
    return expression.match(document).hasMatch() ? fallback : QString();
}

QString crawlerFormTextContent(const QString &fragment)
{
    // gui.exe:0x1400EE440.
    static const QRegularExpression tagExpression(QStringLiteral("<[^<>]*>"));
    QString text = fragment;
    text.replace(tagExpression, QStringLiteral("\n"));
    return text.simplified();
}

HtmlFormInput crawlerSelectInputFromOptionFragments(const QString &selectFragment,
                                                    const QList<QString> &optionFragments)
{
    // gui.exe:0x1400EFE00. The native routine starts with a default input
    // entry, gets the select name with an empty fallback, then fixes its type.
    HtmlFormInput input;
    input.field00 = crawlerFirstElementAttributeOrFallback(
        selectFragment, QStringLiteral("select"), QStringLiteral("name"), QString());
    input.field30 = QStringLiteral("select");

    for (const QString &optionFragment : optionFragments) {
        const QString value = crawlerFirstElementAttributeOrFallback(
            optionFragment, QStringLiteral("option"), QStringLiteral("value"), QString());
        input.field48.append(value);

        const QString selected = crawlerFirstElementAttributeOrFallback(
            optionFragment, QStringLiteral("option"), QStringLiteral("selected"),
            QStringLiteral("true"));
        if (QVariant(selected).toBool()) {
            input.field18 = value;
            input.field60.append(value);
        }
    }
    return input;
}
