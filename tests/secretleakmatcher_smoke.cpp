#include "secretleakmatcher.h"

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

SecretLeakCompiledRule globalRule()
{
    SecretLeakCompiledRule rule;
    rule.global.field0 = QStringLiteral("id");
    rule.global.field24 = QStringLiteral("description");
    rule.global.expression = QRegularExpression(QStringLiteral("(token)"));
    return rule;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString body = QStringLiteral("token token");
    const QString url = QStringLiteral("https://example.test/path");

    SecretLeakCompiledRule pathOnly;
    pathOnly.global.field0 = QStringLiteral("path-id");
    pathOnly.pathExpression = QRegularExpression(QStringLiteral("example\\.test"));
    const QList<SecretLeakMatchRecord> pathMatches = secretLeakRuleMatches(pathOnly, body, url);
    require(pathMatches.size() == 1 && pathMatches.first().field24 == url
                && pathMatches.first().rawCapture.isNull(),
            "path-only route emits its one native-shaped record");
    require(secretLeakRuleMatches(pathOnly, body, QStringLiteral("https://other.test")).isEmpty(),
            "path-only route requires URL match");

    SecretLeakCompiledRule routed = globalRule();
    routed.pathExpression = QRegularExpression(QStringLiteral("example\\.test"));
    routed.bodyPreconditionExpression = QRegularExpression(QStringLiteral("token"));
    require(secretLeakRuleMatches(routed, body, url).size() == 2,
            "matching path and body precondition enter global route");

    routed.bodyPreconditionExpression = QRegularExpression(QStringLiteral("absent"));
    require(secretLeakRuleMatches(routed, body, url).isEmpty(),
            "nonmatching body precondition blocks global route");
    routed = globalRule();
    routed.pathExpression = QRegularExpression(QStringLiteral("other\\.test"));
    require(secretLeakRuleMatches(routed, body, url).isEmpty(),
            "nonmatching path expression blocks global route");
    return 0;
}
