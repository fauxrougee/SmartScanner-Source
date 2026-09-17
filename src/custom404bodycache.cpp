#include "custom404bodycache.h"

#include "custom404urlscope.h"
#include "urlnormalizer.h"

quint64 custom404DirectoryBodyKey(const QUrl &url)
{
    // gui.exe:0x14014BE50 calls 0x140150840, then 0x140123470 with flag 14,
    // and finally qHash(QStringView, 0). Its tree lookup stores only this
    // numeric hash, so collisions are intentionally not disambiguated here.
    const QString parent = custom404ParentDirectoryKey(url);
    const QString canonical = UrlNormalizer::canonical(QUrl::fromUserInput(parent), 14);
    return qHash(QStringView(canonical), 0);
}

QByteArray custom404LookupDirectoryBody(const QHash<quint64, QByteArray> &bodies,
                                        const QUrl &url)
{
    // gui.exe:0x14014F3B0 constructs a default QByteArray (null, not merely
    // empty) when the numeric key is absent.
    return bodies.value(custom404DirectoryBodyKey(url));
}
