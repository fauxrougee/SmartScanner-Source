#include "secretleakmatchrecord.h"

#include <QCoreApplication>

#include <cstdlib>
#include <iostream>

namespace {

void require(bool value, const char *message)
{
    if (!value) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    const SecretLeakMatchRecord global = secretLeakGlobalMatchRecord(
        QStringLiteral("id"), QStringLiteral("description"), QStringLiteral(" raw "),
        QStringLiteral("raw"), 17, 3.25);
    require(global.field0 == QStringLiteral("id")
                && global.field24 == QStringLiteral("description"),
            "global route retains first two QString fields");
    require(global.rawCapture == QStringLiteral(" raw ")
                && global.selectedCapture == QStringLiteral("raw"),
            "global route preserves raw and selected captures separately");
    require(global.capturedStart == 17 && global.score == 3.25,
            "global route retains start and score fields");

    const SecretLeakMatchRecord path = secretLeakPathMatchRecord(
        QStringLiteral("path-rule"), QStringLiteral("https://example.test"));
    require(path.field0 == QStringLiteral("path-rule")
                && path.field24 == QStringLiteral("https://example.test"),
            "path route retains its two observed QString fields");
    require(path.rawCapture.isNull() && path.selectedCapture.isNull()
                && path.capturedStart == 0 && path.score == 0.0,
            "path route preserves native empty and zero tail fields");
    return 0;
}
