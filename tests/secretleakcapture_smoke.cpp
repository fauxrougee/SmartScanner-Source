#include "secretleakcapture.h"

#include <QCoreApplication>
#include <QRegularExpression>

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
    const QRegularExpression noGroups(QStringLiteral("  value  "));
    const SecretLeakCaptureSelection whole = secretLeakSelectCapture(
        noGroups.match(QStringLiteral("  value  ")), false, 0);
    require(whole.rawCapture == QStringLiteral("  value  ")
                && whole.selectedCapture == QStringLiteral("value")
                && whole.capturedStart == 0,
            "no groups retains raw capture and selects trimmed full match");

    const QRegularExpression groups(QStringLiteral("(  first  )-(second)"));
    const QRegularExpressionMatch match = groups.match(QStringLiteral("  first  -second"));
    const SecretLeakCaptureSelection first = secretLeakSelectCapture(match, false, 0);
    require(first.selectedCapture == QStringLiteral("  first  "),
            "fallback selects first non-empty group without trimming");

    const SecretLeakCaptureSelection second = secretLeakSelectCapture(match, true, 2);
    require(second.selectedCapture == QStringLiteral("second"),
            "enabled in-range explicit group overrides fallback");

    const SecretLeakCaptureSelection outOfRange = secretLeakSelectCapture(match, true, 3);
    require(outOfRange.selectedCapture == QStringLiteral("  first  "),
            "out-of-range explicit group falls back to first non-empty group");

    // gui.exe:0x140054A2F accepts explicitCaptureIndex == lastCapturedIndex.
    // Explicit group 2 differs from the fallback's first non-empty group 1.
    const QRegularExpression trailingSecond(QStringLiteral("(a)(b)"));
    const SecretLeakCaptureSelection boundaryLast = secretLeakSelectCapture(
        trailingSecond.match(QStringLiteral("ab")), true, 2);
    require(boundaryLast.selectedCapture == QStringLiteral("b"),
            "explicit last capture is accepted instead of fallback group one");

    const QRegularExpression optional(QStringLiteral("(a)?(b)"));
    const SecretLeakCaptureSelection skipEmpty = secretLeakSelectCapture(
        optional.match(QStringLiteral("b")), false, 0);
    require(skipEmpty.selectedCapture == QStringLiteral("b"),
            "fallback skips empty group before selecting later group");
    return 0;
}
