#pragma once

#include <QList>
#include <QRegularExpression>
#include <QString>

// Source-reconstruction fields for one 0x140046120 exclusion entry.  These
// names describe observed inputs, not recovered native member names.
struct SecretLeakAllowlistEntry {
    QList<QRegularExpression> pathExpressions;
    QList<QRegularExpression> targetExpressions;
    QRegularExpression selectedExpression;
    QString condition;
    QString regexTarget;
};

// Reconstruction label for gui.exe:0x140046120. Returns true when one native
// allowlist entry excludes the candidate; it deliberately preserves the native
// early false paths for AND entries.
[[nodiscard]] bool secretLeakAllowlistExcludes(
    const QString &selectedCapture, const QString &rawCapture,
    const QString &contextLine, const QString &url,
    const QList<SecretLeakAllowlistEntry> &entries);
