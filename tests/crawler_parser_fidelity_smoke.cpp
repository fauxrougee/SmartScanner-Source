#include "crawlerscriptparser.h"
#include "crawlerformparser.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDebug>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QUrl page(QStringLiteral("https://example.invalid/dir/page.html"));
    auto sha1 = [](const QByteArray &bytes) { return QCryptographicHash::hash(bytes, QCryptographicHash::Sha1).toHex(); };
    // Native QString length tests accept both absent and explicitly empty attrs.
    const auto empty = crawlerParseScripts(page, QStringLiteral("<script type=\"\" src=\"\">A</script>"));
    if (empty.fingerprint != sha1("A") || !empty.sourceLocations.isEmpty()) {
        qCritical() << "Empty script attributes do not match native length gates";
        return 1;
    }
    const auto absent = crawlerParseScripts(page, QStringLiteral("<script>A</script>"));
    if (absent.fingerprint != sha1("A")) return 2;
    // Regex is case-insensitive, but native type-value comparisons use enum 1.
    for (const QString type : {QStringLiteral("MODULE"), QStringLiteral("TEXT/JAVASCRIPT"), QStringLiteral("application/json")}) {
        const auto rejected = crawlerParseScripts(page, QStringLiteral("<script type=\"%1\">A</script>").arg(type));
        if (rejected.fingerprint != sha1({})) return 3;
    }
    for (const QString type : {QStringLiteral("module"), QStringLiteral("text/javascript")}) {
        if (crawlerParseScripts(page, QStringLiteral("<script type=\"%1\">A</script>").arg(type)).fingerprint != sha1("A")) return 4;
    }
    const auto relative = crawlerParseScripts(page,
        QStringLiteral("<base href=\"/assets/\"><script src=\"x.js?v=2#part\"></script>"));
    if (relative.sourceLocations != QList<QUrl>{QUrl(QStringLiteral("https://example.invalid/assets/x.js?v=2#part"))}
        || relative.fingerprint != sha1("https://example.invalid/assets/x.js")) return 5;

    // Native input loop advances the text boundary even for discarded inputs.
    const auto forms = crawlerHtmlForms(page, QStringLiteral(
        "<form><b>First</b><input name='a'>Drop<input type='reset' name='r'>Second<input name='b'></form>"));
    if (forms.size() != 1 || forms[0].field98.size() != 2) return 6;
    if (forms[0].field98[0].field80 != QStringLiteral("First")
        || forms[0].field98[1].field80 != QStringLiteral("Second")) return 7;
    const auto textareas = crawlerHtmlForms(page, QStringLiteral(
        "<form><textarea name=\"\">discard</textarea><textarea name='kept'>value</textarea></form>"));
    if (textareas.size() != 1 || textareas[0].field98.size() != 1
        || textareas[0].field98[0].field00 != QStringLiteral("kept")
        || textareas[0].field98[0].field18 != QStringLiteral("value")) return 8;
    return 0;
}
