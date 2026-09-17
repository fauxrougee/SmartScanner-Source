#include "urlnormalizer.h"

#include <QUrlQuery>

#include <algorithm>

namespace UrlNormalizer {

QUrl withoutDefaultPort(QUrl url)
{
    const int port = url.port(-1);
    if (port == -1)
        return url;

    const QString scheme = url.scheme().toLower();
    if ((scheme == QStringLiteral("http") && port == 80)
        || (scheme == QStringLiteral("https") && port == 443))
        url.setPort(-1);
    return url;
}

QUrl withoutUnqueriedRootSlash(QUrl url)
{
    if (url.path().trimmed() != QStringLiteral("/") || url.hasQuery())
        return url;

    const QString serialized = url.toString();
    return QUrl(serialized.left(serialized.size() - url.path().size()));
}

QUrl withoutDefaultDocument(QUrl url)
{
    static const QStringList defaultDocuments{
        QStringLiteral("index.html"), QStringLiteral("index.htm"),
        QStringLiteral("index.php"), QStringLiteral("default.html"),
        QStringLiteral("index.shtml"), QStringLiteral("default.htm"),
        QStringLiteral("home.html"), QStringLiteral("home.htm"),
        QStringLiteral("default.asp"), QStringLiteral("index.php5"),
        QStringLiteral("index.php4"), QStringLiteral("index.php3"),
        QStringLiteral("index.cgi"), QStringLiteral("iisstart.htm"),
        QStringLiteral("default.aspx")};

    if (!defaultDocuments.contains(url.fileName(QUrl::FullyDecoded), Qt::CaseInsensitive))
        return url;
    return QUrl(url.toString(QUrl::RemoveFilename));
}

QUrl withSortedQueryItems(QUrl url, bool clearValues)
{
    QUrlQuery query(url);
    auto items = query.queryItems();
    std::sort(items.begin(), items.end(), [](const auto &left, const auto &right) {
        // QtPrivate::compareStrings(..., Qt::CaseSensitive) on item.first.
        return QString::compare(left.first, right.first, Qt::CaseSensitive) < 0;
    });
    if (clearValues) {
        for (auto &item : items)
            item.second.clear();
    }
    query.setQueryItems(items);
    url.setQuery(query);
    return url;
}

QString canonical(const QUrl &input, quint8 flags)
{
    // gui.exe:0x140123500. Bits 0x20 and 0x40 select RemoveQuery and
    // RemovePath respectively during the initial reparse.
    auto format = QUrl::NormalizePathSegments | QUrl::RemoveUserInfo | QUrl::RemoveFragment;
    if ((flags & 0x20) != 0)
        format |= QUrl::RemoveQuery;
    if ((flags & 0x40) != 0)
        format |= QUrl::RemovePath;
    QUrl url(input.toString(format));
    if ((flags & 0x40) != 0)
        url.setPath(QStringLiteral("/"));
    url.setHost(url.host(QUrl::FullyDecoded).toLower());
    url = withoutDefaultPort(std::move(url));
    url = withSortedQueryItems(std::move(url), (flags & 0x10) != 0);

    if ((flags & 0x02) != 0) {
        QString host = url.host(QUrl::FullyDecoded);
        if (host.startsWith(QStringLiteral("www."), Qt::CaseSensitive)) {
            host.remove(0, 4);
            url.setHost(host);
        }
    }

    if ((flags & 0x08) != 0)
        url = withoutDefaultDocument(std::move(url));

    if ((flags & 0x01) != 0) {
        if (url.path().isEmpty())
            url.setPath(QStringLiteral("/"));
    } else {
        url = withoutUnqueriedRootSlash(std::move(url));
    }

    const QString scheme = url.scheme().toLower();
    if ((flags & 0x04) != 0 && scheme != QStringLiteral("http")
        && scheme != QStringLiteral("https") && url.port(-1) == -1) {
        // gui.exe:0x1401242E0 sets an empty scheme and removes the leading
        // two slash characters from its serialized form.
        url.setScheme({});
        return url.toString().mid(2);
    }
    return url.toString();
}

QString canonicalForIssue(const QUrl &input)
{
    return canonical(input, 46);
}

} // namespace UrlNormalizer
