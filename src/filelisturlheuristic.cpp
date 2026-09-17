#include "filelisturlheuristic.h"

#include <QRegularExpression>

namespace {

QString extensionOf(const QUrl &url)
{
    // gui.exe:0x14014F510
    const QString fileName = url.fileName(QUrl::FullyDecoded);
    const qsizetype dot = fileName.lastIndexOf(u'.', -1, Qt::CaseSensitive);
    return dot == -1 ? QString{} : fileName.sliced(dot + 1);
}

const QRegularExpression &dynamicExtensionExpression()
{
    static const QRegularExpression expression(
        QStringLiteral("^(asp|aspx|axd|asx|asmx|ashx|cfm|yaws|jsp|jspx|wss|do|action|pl|php|php4|php3|phtml|py|rb|rhtml|shtml|cgi|dll)$"),
        QRegularExpression::CaseInsensitiveOption);
    return expression;
}

const QRegularExpression &repeatedHyphenExpression()
{
    static const QRegularExpression expression(
        QStringLiteral("(\\w+-){3,}\\w+"), QRegularExpression::CaseInsensitiveOption);
    return expression;
}

const QRegularExpression &longPathComponentExpression()
{
    static const QRegularExpression expression(QStringLiteral("/[^/]{20,}/"));
    return expression;
}

const QRegularExpression &yearPathExpression()
{
    static const QRegularExpression expression(QStringLiteral("/20[12]\\d/"));
    return expression;
}

const QRegularExpression &nonAsciiExpression()
{
    static const QRegularExpression expression(QStringLiteral("[^ -~]+"));
    return expression;
}

} // namespace

bool fileListUrlHeuristic(const QUrl &url, bool *extensionlessFileName)
{
    // gui.exe:0x14014FA50
    const QString extension = extensionOf(url);
    const QString fileName = url.fileName(QUrl::FullyDecoded);
    if (!fileName.isEmpty() && extension.isEmpty()) {
        if (extensionlessFileName)
            *extensionlessFileName = true;
        return true;
    }

    if (dynamicExtensionExpression().match(extension).hasMatch())
        return false;

    const QString path = url.path(QUrl::FullyDecoded);
    if (path.size() > 100 || repeatedHyphenExpression().match(path).hasMatch()
        || longPathComponentExpression().match(path).hasMatch())
        return true;

    if (path.contains(QStringLiteral("/tag/"), Qt::CaseSensitive)
        || path.contains(QStringLiteral("/tags/"), Qt::CaseSensitive)
        || path.contains(QStringLiteral("/category/"), Qt::CaseSensitive)
        || path.contains(QStringLiteral("/author/"), Qt::CaseSensitive)
        || yearPathExpression().match(path).hasMatch())
        return true;

    return nonAsciiExpression().match(path).hasMatch()
        || path.count(u'/', Qt::CaseSensitive) > 8;
}
