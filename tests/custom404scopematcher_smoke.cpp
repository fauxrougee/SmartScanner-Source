#include "custom404scopematcher.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    if (!custom404MatchesStoredScope(QStringLiteral("https://www.example.test/app/?q=ignored"),
                                     {QStringLiteral("https://example.test/app/")})) {
        return 1;
    }
    if (!custom404MatchesStoredScope(QStringLiteral("https://example.test/app/child"),
                                     {QStringLiteral("https://example.test/app")})) {
        return 2;
    }
    if (!custom404MatchesStoredScope(QStringLiteral("https://example.test/app/"),
                                     {QStringLiteral("https://example.test/app")})) {
        return 3;
    }
    if (custom404MatchesStoredScope(QStringLiteral("https://example.test/application"),
                                    {QStringLiteral("https://example.test/app")})) {
        return 4;
    }
    return 0;
}
