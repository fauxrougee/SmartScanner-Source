#include "secretleakallowlist.h"

namespace {

bool anyMatch(const QList<QRegularExpression> &expressions, const QString &subject)
{
    for (const QRegularExpression &expression : expressions) {
        if (expression.match(subject).hasMatch())
            return true;
    }
    return false;
}

} // namespace

bool secretLeakAllowlistExcludes(
    const QString &selectedCapture, const QString &rawCapture,
    const QString &contextLine, const QString &url,
    const QList<SecretLeakAllowlistEntry> &entries)
{
    // gui.exe:0x140046120.  The native walks entries in order, uses the first
    // matching regex in either list, and returns false immediately when an AND
    // entry's path list has no match or one target expression fails.
    for (const SecretLeakAllowlistEntry &entry : entries) {
        const bool pathMatched = anyMatch(entry.pathExpressions, url);
        if (!pathMatched && entry.condition == QStringLiteral("AND"))
            return false;

        const QString &target = entry.regexTarget == QStringLiteral("line")
            ? contextLine
            : entry.regexTarget == QStringLiteral("match") ? rawCapture : selectedCapture;

        bool targetMatched = false;
        for (const QRegularExpression &expression : entry.targetExpressions) {
            if (expression.match(target).hasMatch()) {
                targetMatched = true;
                break;
            }
            if (entry.condition == QStringLiteral("AND"))
                return false;
        }

        const bool selectedMatched = !entry.selectedExpression.pattern().isEmpty()
            && entry.selectedExpression.match(selectedCapture).hasMatch();
        if (entry.condition == QStringLiteral("OR")
            && (pathMatched || targetMatched || selectedMatched)) {
            return true;
        }
        if (entry.condition == QStringLiteral("AND")
            && pathMatched && targetMatched && selectedMatched) {
            return true;
        }
    }
    return false;
}
