#include "custom404similarity.h"

#include <QCoreApplication>
#include <QtGlobal>

namespace {

bool nearlyEqual(double actual, double expected)
{
    return qAbs(actual - expected) < 0.0001;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    const QString normalized = Custom404Similarity::normalizePageText(
        QStringLiteral("<STYLE>hidden</STYLE><script>drop()</script><b>Hello</b>,--World!!"));
    if (normalized
        != QStringLiteral("Hello --World"))
    {
        return 1;
    }

    if (!nearlyEqual(Custom404Similarity::score(QStringLiteral("<b>same</b>"),
                                                  QStringLiteral("same")), 100.0))
    {
        return 2;
    }

    // gui.exe counts every item in the shorter split list that occurs at least
    // once in the longer list; duplicates in the longer list are not removed.
    if (!nearlyEqual(Custom404Similarity::score(QStringLiteral("alpha beta beta"),
                                                  QStringLiteral("alpha beta")), 80.0))
    {
        return 3;
    }

    if (!nearlyEqual(Custom404Similarity::score(QByteArray("same\0page", 9),
                                                  QByteArray("same page")), 100.0))
    {
        return 4;
    }

    if (!nearlyEqual(Custom404Similarity::score(QStringLiteral("a"),
                                                  QStringLiteral("1234567890")), 1.0 / 11.0))
    {
        return 5;
    }

    return 0;
}
