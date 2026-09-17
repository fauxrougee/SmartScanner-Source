#include "custom404bodycache.h"
#include "custom404cachedecision.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QUrl url(QStringLiteral("https://example.test/area/item.php"));
    QUrl root(url);
    root.setPath(QStringLiteral("/"), QUrl::DecodedMode);
    QHash<quint64, QByteArray> bodies;
    bodies.insert(custom404DirectoryBodyKey(root), QByteArrayLiteral("root baseline body"));
    bodies.insert(custom404DirectoryBodyKey(url), QByteArrayLiteral("directory baseline body"));

    const QByteArray candidate = QByteArrayLiteral("new distinct candidate");
    if (custom404CachedBodyDecision(candidate, url, true, bodies, {}) != -2)
        return 1;
    if (custom404CachedBodyDecision(candidate, url, false, bodies,
                                    {QStringLiteral("https://example.test/area/")})
        != -2) {
        return 2;
    }
    if (custom404CachedBodyDecision(candidate, url, false, bodies, {}) != 1)
        return 3;
    if (custom404CachedBodyDecision(QByteArrayLiteral("root baseline body"), url, false,
                                    bodies, {}) != 0)
        return 4;
    bodies.remove(custom404DirectoryBodyKey(url));
    if (custom404CachedBodyDecision(candidate, url, false, bodies, {}) != 3)
        return 5;
    return 0;
}
