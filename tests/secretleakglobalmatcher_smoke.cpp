#include "secretleakglobalmatcher.h"

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

SecretLeakGlobalRule tokenRule()
{
    SecretLeakGlobalRule rule;
    rule.field0 = QStringLiteral("rule-id");
    rule.field24 = QStringLiteral("rule-description");
    rule.expression = QRegularExpression(QStringLiteral("(token)"));
    return rule;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString body = QStringLiteral("first token\nsecond token");
    const QString url = QStringLiteral("https://example.test/path");

    SecretLeakGlobalRule rule = tokenRule();
    const QList<SecretLeakMatchRecord> matches = secretLeakGlobalMatches(rule, body, url);
    require(matches.size() == 2, "global path emits every surviving match");
    require(matches.at(0).field0 == QStringLiteral("rule-id")
                && matches.at(0).field24 == QStringLiteral("rule-description"),
            "global path copies observed rule fields into every record");
    require(matches.at(0).rawCapture == QStringLiteral("token")
                && matches.at(0).selectedCapture == QStringLiteral("token"),
            "global path retains raw and selected capture values");
    require(matches.at(0).capturedStart == 6 && matches.at(1).capturedStart == 19,
            "global path retains capturedStart per occurrence");

    rule.requiresMinimumEntropy = true;
    rule.minimumEntropy = 99.0;
    require(secretLeakGlobalMatches(rule, body, url).isEmpty(),
            "entropy threshold suppresses a candidate before append");

    rule = tokenRule();
    SecretLeakAllowlistEntry excluded;
    excluded.condition = QStringLiteral("OR");
    excluded.targetExpressions << QRegularExpression(QStringLiteral("token"));
    rule.globalAllowlist << excluded;
    require(secretLeakGlobalMatches(rule, body, url).isEmpty(),
            "either native allowlist source suppresses global candidate");
    return 0;
}
