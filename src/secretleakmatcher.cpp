#include "secretleakmatcher.h"

QList<SecretLeakMatchRecord> secretLeakRuleMatches(
    const SecretLeakCompiledRule &rule, const QString &body, const QString &url)
{
    // gui.exe:0x140054506-0x140054981. The body expression is the +56 field,
    // pathExpression the +64 field, and bodyPreconditionExpression the +48
    // field. Empty-pattern checks follow QRegularExpression::pattern().
    const bool hasBodyExpression = !rule.global.expression.pattern().isEmpty();
    const bool hasPathExpression = !rule.pathExpression.pattern().isEmpty();

    // 0x14005450d-0x1400547bd: when +56 is empty and +64 is non-empty, a
    // successful URL hasMatch creates at most one special record; the native
    // passes three copies of that URL plus the URL subject to both allowlists.
    if (!hasBodyExpression && hasPathExpression) {
        if (!rule.pathExpression.match(url).hasMatch())
            return {};
        if (secretLeakAllowlistExcludes(url, url, url, url, rule.global.globalAllowlist)
            || secretLeakAllowlistExcludes(url, url, url, url, rule.global.ruleAllowlist)) {
            return {};
        }
        return {secretLeakPathMatchRecord(rule.global.field0, url)};
    }

    // 0x1400547d4-0x140054866: a non-empty +64 expression that does not match
    // the URL prevents the global route. An empty +64 field does not gate it.
    if (hasPathExpression && !rule.pathExpression.match(url).hasMatch())
        return {};
    if (!hasBodyExpression)
        return {};

    // 0x14005487e-0x14005495e: a non-empty +48 expression must match the body
    // before the +56 expression's globalMatch iterator is entered.
    if (!rule.bodyPreconditionExpression.pattern().isEmpty()
        && !rule.bodyPreconditionExpression.match(body).hasMatch()) {
        return {};
    }
    return secretLeakGlobalMatches(rule.global, body, url);
}

QList<SecretLeakMatchRecord> secretLeakMatches(
    const SecretLeakConfig &config, const QString &body, const QString &url)
{
    // 0x1400544CC-0x1400544D3: *a2 = a2[1] = a2[2] = 0.
    QList<SecretLeakMatchRecord> records;
    // 0x1400544E0-0x1400544EE / 0x140054CB5-0x140054CBD: v8 walks a1[0]..a1[1]
    // in steps of 120; every per-rule early exit jumps to LABEL_63 (next rule).
    for (const SecretLeakCompiledRule &nativeRule : config.rules) {
        SecretLeakCompiledRule rule = nativeRule;
        // Both 0x140046120 call sites pass a1+3 (a1+24) as the first list.
        rule.global.globalAllowlist = config.globalAllowlist;
        records.append(secretLeakRuleMatches(rule, body, url));
    }
    return records;
}
