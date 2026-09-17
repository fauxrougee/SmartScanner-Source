#pragma once

#include "secretleakallowlist.h"

#include <QList>
#include <QRegularExpression>

#include "secretleakmatchrecord.h"

// Source-reconstruction inputs for the globalMatch path in gui.exe:0x140054490.
// They are not a recovered TOML or ABI layout.
struct SecretLeakGlobalRule {
    QString field0;
    QString field24;
    QRegularExpression expression;
    bool useExplicitCaptureIndex = false;
    qint32 explicitCaptureIndex = 0;
    bool requiresMinimumEntropy = false;
    double minimumEntropy = 0.0;
    QList<SecretLeakAllowlistEntry> globalAllowlist;
    QList<SecretLeakAllowlistEntry> ruleAllowlist;
};

// Reconstruction label for the globalMatch branch of gui.exe:0x140054490 only.
[[nodiscard]] QList<SecretLeakMatchRecord> secretLeakGlobalMatches(
    const SecretLeakGlobalRule &rule, const QString &body, const QString &url);
