#include "custom404bodycache.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QUrl first(QStringLiteral("https://www.example.test/one/item.php?q=ignored"));
    const QUrl sameDirectory(QStringLiteral("https://example.test/one/other.html"));
    const QUrl otherDirectory(QStringLiteral("https://example.test/two/item.php"));
    QHash<quint64, QByteArray> bodies;
    bodies.insert(custom404DirectoryBodyKey(first), QByteArrayLiteral("stored-body"));

    if (custom404DirectoryBodyKey(first) != custom404DirectoryBodyKey(sameDirectory)
        || custom404LookupDirectoryBody(bodies, sameDirectory) != QByteArrayLiteral("stored-body")) {
        return 1;
    }
    if (custom404LookupDirectoryBody(bodies, otherDirectory).isNull() == false)
        return 2;
    return 0;
}
