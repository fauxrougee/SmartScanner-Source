#include "crawlerformparser.h"

#include "crawlerformexpressions.h"
#include "crawlerparsehelpers.h"
#include "sitemaplocation.h"

namespace {

QString formAttribute(const QString &fragment, const QString &attribute,
                      const QString &fallback = {})
{
    return crawlerFirstElementAttributeOrFallback(fragment, QStringLiteral("form"), attribute,
                                                  fallback);
}

QString inputAttribute(const QString &fragment, const QString &attribute,
                       const QString &fallback = {})
{
    return crawlerFirstElementAttributeOrFallback(fragment, QStringLiteral("input"), attribute,
                                                  fallback);
}

HtmlFormInput inputFromFragment(const QString &fragment)
{
    // gui.exe:0x1400EE560. The native caller discards the default entry when
    // its name is null; returning the same null-name entry keeps that decision
    // at the document loop below.
    HtmlFormInput input;
    input.field00 = inputAttribute(fragment, QStringLiteral("name"));
    // `QString::compare_helper` at 0x1400EEA2E compares against the empty
    // literal before the entry construction, so both null and empty names are
    // discarded by the caller.
    if (input.field00.isEmpty()) {
        input.field00 = QString();
        return input;
    }

    input.field18 = inputAttribute(fragment, QStringLiteral("value"));
    if (input.field18.isNull())
        input.field18 = QStringLiteral("");
    input.field78 = !inputAttribute(fragment, QStringLiteral("checked"),
                                    QStringLiteral("1")).isNull();
    input.field30 = inputAttribute(fragment, QStringLiteral("type")).toLower();
    if (input.field30.compare(QStringLiteral("reset"), Qt::CaseInsensitive) == 0) {
        input.field00 = QString();
        return input;
    }

    QRegularExpressionMatchIterator attributes =
        crawlerFormAttributeExpression().globalMatch(fragment);
    while (attributes.hasNext()) {
        const QRegularExpressionMatch match = attributes.next();
        const QString key = match.captured(1);
        QString value = match.captured(2);
        if (value.startsWith(QLatin1Char('\'')) || value.startsWith(QLatin1Char('"')))
            value = value.mid(1, value.size() - 2);
        input.field98.insert(key, value);
    }
    return input;
}

} // namespace

QList<HtmlForm> crawlerHtmlForms(const QUrl &responseUrl, const QString &document)
{
    // gui.exe:0x1400EEF70. Every outer match starts as HtmlForm, then the
    // method is reset to GET unless its lower-cased text equals "post".
    QList<HtmlForm> forms;
    QRegularExpressionMatchIterator formMatches = crawlerFormExpression().globalMatch(document);
    while (formMatches.hasNext()) {
        const QString fragment = formMatches.next().captured(0);
        HtmlForm form;
        form.target = resolveSitemapLocation(responseUrl,
                                             formAttribute(fragment, QStringLiteral("action")))
                          .toString();
        form.field20 = formAttribute(fragment, QStringLiteral("method")).toLower()
                           == QStringLiteral("post")
                       ? 2
                       : 1;
        form.setStandardHeader(HttpRequestItem::StandardHeader::Referer,
                               responseUrl.toString().toUtf8());
        if (formAttribute(fragment, QStringLiteral("enctype")).toLower()
            == QStringLiteral("multipart/form-data")) {
            form.setStandardHeader(HttpRequestItem::StandardHeader::ContentType,
                                   QByteArrayLiteral("multipart/form-data"));
        }

        QRegularExpressionMatchIterator inputMatches = crawlerInputExpression().globalMatch(fragment);
        qsizetype previousEnd = 0;
        while (inputMatches.hasNext()) {
            // gui.exe:0x1400EF5CD..0x1400EF6EE: consume the intervening
            // text and advance the boundary even when the input is rejected.
            const QRegularExpressionMatch match = inputMatches.next();
            const QString precedingText = crawlerFormTextContent(
                fragment.mid(previousEnd, match.capturedStart(0) - previousEnd));
            HtmlFormInput input = inputFromFragment(match.captured(0));
            previousEnd = match.capturedEnd(0);
            if (!input.field00.isNull()) {
                input.field80 = precedingText;
                form.field98.append(std::move(input));
            }
        }

        QRegularExpressionMatchIterator selectMatches = crawlerSelectExpression().globalMatch(fragment);
        while (selectMatches.hasNext()) {
            const QString selectFragment = selectMatches.next().captured(0);
            QList<QString> optionFragments;
            QRegularExpressionMatchIterator optionMatches =
                crawlerOptionExpression().globalMatch(selectFragment);
            while (optionMatches.hasNext())
                optionFragments.append(optionMatches.next().captured(0));
            form.field98.append(
                crawlerSelectInputFromOptionFragments(selectFragment, optionFragments));
        }

        QRegularExpressionMatchIterator textareaMatches =
            crawlerTextareaExpression().globalMatch(fragment);
        while (textareaMatches.hasNext()) {
            const QRegularExpressionMatch textarea = textareaMatches.next();
            HtmlFormInput input;
            input.field00 = crawlerFirstElementAttributeOrFallback(
                // The native literal is "input", even in this textarea path
                // (gui.exe:0x1400EFA21); retain its DOM/regex fallback behavior.
                textarea.captured(0), QStringLiteral("input"), QStringLiteral("name"), QString());
            // gui.exe:0x1400EFC03 tests the QString length, not isNull().
            if (!input.field00.isEmpty()) {
                input.field18 = textarea.captured(2);
                input.field30 = QStringLiteral("textarea");
                form.field98.append(std::move(input));
            }
        }
        forms.append(std::move(form));
    }
    return forms;
}
