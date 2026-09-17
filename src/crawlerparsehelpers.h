#pragma once

#include <QList>
#include <QRegularExpressionMatch>
#include <QUrl>

class HtmlFormInput;

// gui.exe:0x14006D970. For the shared quoted/unquoted attribute expressions,
// capture group 2 is preferred unless it is a null QString; group 3 is then
// used. An empty quoted attribute remains distinct from an unmatched capture.
[[nodiscard]] QString crawlerAttributeCapture(const QRegularExpressionMatch &match);

// gui.exe:0x1401374B0. Returns the first matching attribute value from an
// element expression built with CaseInsensitiveOption. The element text is
// intentionally inserted verbatim; only the attribute name is escaped.
[[nodiscard]] QString crawlerFirstElementAttribute(const QString &document,
                                                    const QString &element,
                                                    const QString &attribute);

// gui.exe:0x140071947 through 0x14007198C. This is the pure base-URL
// extraction and resolution portion of the shared CrawlerParser handler.
[[nodiscard]] QUrl crawlerDocumentBaseUrl(const QUrl &requestUrl, const QString &document);

// gui.exe:0x1400EDC70. It first reads an attribute from the first matching
// QDom element. If that value is null, it falls back to the exact three regex
// forms below. A missing attribute returns a null QString; a present but empty
// attribute is distinguished from that case.
[[nodiscard]] QString crawlerFirstElementAttributeOrFallback(const QString &document,
                                                              const QString &element,
                                                              const QString &attribute,
                                                              const QString &fallback);

// gui.exe:0x1400EE440. Replaces every non-nested tag with a newline, then
// applies QString::simplified(). The form route uses this for text adjacent to
// input-tag matches.
[[nodiscard]] QString crawlerFormTextContent(const QString &fragment);

// gui.exe:0x1400EFE00. This is the select-entry transformation once the
// native outer and option expressions have supplied their matching fragments.
// Fragment matching is deliberately kept out of this helper until those
// expressions are recovered.
[[nodiscard]] HtmlFormInput crawlerSelectInputFromOptionFragments(
    const QString &selectFragment, const QList<QString> &optionFragments);
