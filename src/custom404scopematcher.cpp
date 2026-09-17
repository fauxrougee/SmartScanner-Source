#include "custom404scopematcher.h"

#include "urlnormalizer.h"

#include <QUrl>

namespace {

QString canonicalScope(const QString &value)
{
    // gui.exe:0x140123470 invokes QUrl::fromUserInput with an empty working
    // directory, then delegates to the flag-driven canonicalizer.
    return UrlNormalizer::canonical(QUrl::fromUserInput(value), 46);
}

} // namespace

bool custom404MatchesStoredScope(const QString &candidate,
                                 const QStringList &storedScopes)
{
    // gui.exe:0x14014D440. The original loop is a read-only traversal of the
    // detector's separate scope collection at offset +0x60.
    const QString current = canonicalScope(candidate);
    for (const QString &storedValue : storedScopes) {
        const QString stored = canonicalScope(storedValue);
        if (stored == current)
            return true;

        if (stored.endsWith(QLatin1Char('/'), Qt::CaseSensitive)) {
            if (current.startsWith(stored, Qt::CaseSensitive))
                return true;
            continue;
        }

        if (current == stored)
            return true;
        if (current.endsWith(QLatin1Char('/'), Qt::CaseSensitive)
            && current.left(current.size() - 1) == stored) {
            return true;
        }
        if (current.size() > stored.size() + 1
            && current.startsWith(stored, Qt::CaseSensitive)
            && current.at(stored.size()) == QLatin1Char('/')) {
            return true;
        }
    }
    return false;
}
