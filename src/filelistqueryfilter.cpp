#include "filelistqueryfilter.h"

#include <QRegularExpression>
#include <QUrlQuery>
#include <QStringView>

namespace {

quint64 queryNameHash(const QString &name, const QString &host, bool packetItem)
{
    // gui.exe:0x140162A90 formats "%1?%2" or "%1?%2^" and hashes the
    // result with seed 1001.
    const QString key = packetItem ? QStringLiteral("%1?%2^").arg(name, host)
                                   : QStringLiteral("%1?%2").arg(name, host);
    return qHash(QStringView(key), 1001);
}

} // namespace

bool fileListHasUnseenQueryName(const QSet<quint64> &seenNames, const QUrl &url,
                                const QList<QPair<QString, QString>> &packetQueryItems)
{
    // gui.exe:0x140162A90
    const QString host = url.host(QUrl::FullyDecoded);
    const QList<QPair<QString, QString>> urlItems = QUrlQuery(url).queryItems();
    for (const auto &item : urlItems) {
        if (!seenNames.contains(queryNameHash(item.first, host, false)))
            return true;
    }
    for (const auto &item : packetQueryItems) {
        if (!seenNames.contains(queryNameHash(item.first, host, true)))
            return true;
    }
    return false;
}

bool fileListRetainsQueryItemForRateLimit(const QPair<QString, QString> &item)
{
    // gui.exe:0x140162F00:
    //   return name in {"a", "module", "class"}
    //       || (!value matches "^\\d+$" && value.length() <= 10);
    // The list and regular expression are static locals in the native code.
    static const QSet<QString> retainedNames{
        QStringLiteral("a"), QStringLiteral("module"), QStringLiteral("class")};
    static const QRegularExpression numericValue(QStringLiteral("^\\d+$"));

    return retainedNames.contains(item.first)
        || (!numericValue.match(item.second).hasMatch() && item.second.size() <= 10);
}
