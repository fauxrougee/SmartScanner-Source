#pragma once

#include "secretleakglobalmatcher.h"

// Source-reconstruction inputs for the route-selection fields at +48/+56/+64
// of a gui.exe:0x140054490 rule. This is not a recovered TOML/ABI layout.
struct SecretLeakCompiledRule {
    SecretLeakGlobalRule global;
    QRegularExpression bodyPreconditionExpression;
    QRegularExpression pathExpression;
};

// Reconstruction label for the complete per-rule branch routing in
// gui.exe:0x140054490. Rule loading remains outside this function.
[[nodiscard]] QList<SecretLeakMatchRecord> secretLeakRuleMatches(
    const SecretLeakCompiledRule &rule, const QString &body, const QString &url);

// Source-reconstruction view of the matcher object passed as a1 to
// gui.exe:0x140054490: a1[0]/a1[1] delimit the 120-byte rule vector and a1+24
// is the global allowlist.  The SecretLeak slot passes qword_140360C88.
// TODO(REVERSE): the producer of qword_140360C88 (TOML loader 0x140047D40 /
// 0x140049750) and the native 120-byte rule layout are not reconstructed.
struct SecretLeakConfig {
    QList<SecretLeakCompiledRule> rules;
    QList<SecretLeakAllowlistEntry> globalAllowlist;
};

// Reconstruction label for the outer rule loop of gui.exe:0x140054490
// (0x1400544CC-0x140054CBD): the output vector is cleared, then every rule is
// evaluated in vector order and its records are appended.  The per-rule
// global allowlist in SecretLeakGlobalRule is overwritten by a1+24.
[[nodiscard]] QList<SecretLeakMatchRecord> secretLeakMatches(
    const SecretLeakConfig &config, const QString &body, const QString &url);
