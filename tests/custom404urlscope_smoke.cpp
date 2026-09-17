#include "custom404urlscope.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QUrl root(QStringLiteral("https://example.test/"));
    const QUrl page(QStringLiteral("https://example.test/one/two/item.php"));
    const QUrl samePage(QStringLiteral("https://example.test/one/two/item.php"));
    const QUrl otherHost(QStringLiteral("https://other.test/one/two/item.php"));
    if (custom404PathSlashCount(root) != 0 || custom404PathSlashCount(page) != 3)
        return 1;
    // The native formatting mask 7360 omits the URL authority here.
    if (custom404PathRoot(page, 2) != QStringLiteral("/"))
        return 2;
    if (!custom404SamePathRoot(page, samePage, true)
        || !custom404SamePathRoot(page, otherHost, true)) {
        return 3;
    }

    // Directory URLs lose one path-count unit before their root is produced.
    const QUrl directory(QStringLiteral("https://example.test/one/two/"));
    if (custom404PathRoot(directory, custom404PathSlashCount(directory) - 1)
        != QStringLiteral("/")) {
        return 4;
    }

    if (custom404ParentDirectoryKey(
            QUrl(QStringLiteral("https://example.test/one/two/item.php?q=ignored")))
            != QStringLiteral("https://example.test/one/two/")
        || custom404ParentDirectoryKey(root) != QStringLiteral("https://example.test/")) {
        return 5;
    }

    return 0;
}
