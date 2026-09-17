#include "secretleakglobalmatcher.h"

#include "secretleakcapture.h"
#include "secretleakentropy.h"

QList<SecretLeakMatchRecord> secretLeakGlobalMatches(
    const SecretLeakGlobalRule &rule, const QString &body, const QString &url)
{
    // gui.exe:0x140054981-0x140054c93. This is only the route which invokes
    // QRegularExpression::globalMatch on the body; the independent path
    // hasMatch route has a different output payload and is not included here.
    QList<SecretLeakMatchRecord> records;
    QRegularExpressionMatchIterator iterator = rule.expression.globalMatch(body);
    while (iterator.hasNext()) {
        const SecretLeakCaptureSelection capture = secretLeakSelectCapture(
            iterator.next(), rule.useExplicitCaptureIndex, rule.explicitCaptureIndex);
        const QString context = secretLeakContextLine(body, capture.capturedStart);
        const double score = secretLeakTextEntropy(capture.selectedCapture);
        if (rule.requiresMinimumEntropy && score < rule.minimumEntropy)
            continue;
        if (secretLeakAllowlistExcludes(capture.selectedCapture, capture.rawCapture,
                                        context, url, rule.globalAllowlist)
            || secretLeakAllowlistExcludes(capture.selectedCapture, capture.rawCapture,
                                           context, url, rule.ruleAllowlist)) {
            continue;
        }
        records.append(secretLeakGlobalMatchRecord(
            rule.field0, rule.field24, capture.rawCapture, capture.selectedCapture,
            capture.capturedStart, score));
    }
    return records;
}
