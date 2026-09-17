#include "secretleakallowlist.h"

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

SecretLeakAllowlistEntry entry(const QString &condition)
{
    SecretLeakAllowlistEntry value;
    value.condition = condition;
    return value;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString selected = QStringLiteral("selected");
    const QString raw = QStringLiteral("raw capture");
    const QString line = QStringLiteral("context line");
    const QString url = QStringLiteral("https://example.test/path");

    require(!secretLeakAllowlistExcludes(selected, raw, line, url, {}),
            "empty allowlist cannot exclude");

    SecretLeakAllowlistEntry orTarget = entry(QStringLiteral("OR"));
    orTarget.targetExpressions << QRegularExpression(QStringLiteral("selected"));
    require(secretLeakAllowlistExcludes(selected, raw, line, url, {orTarget}),
            "OR excludes when default selected target matches");

    SecretLeakAllowlistEntry lineTarget = entry(QStringLiteral("OR"));
    lineTarget.regexTarget = QStringLiteral("line");
    lineTarget.targetExpressions << QRegularExpression(QStringLiteral("context"));
    require(secretLeakAllowlistExcludes(selected, raw, line, url, {lineTarget}),
            "line selector applies target regex to context line");

    SecretLeakAllowlistEntry rawTarget = entry(QStringLiteral("OR"));
    rawTarget.regexTarget = QStringLiteral("match");
    rawTarget.targetExpressions << QRegularExpression(QStringLiteral("raw"));
    require(secretLeakAllowlistExcludes(selected, raw, line, url, {rawTarget}),
            "match selector applies target regex to raw capture");

    SecretLeakAllowlistEntry all = entry(QStringLiteral("AND"));
    all.pathExpressions << QRegularExpression(QStringLiteral("example\\.test"));
    all.targetExpressions << QRegularExpression(QStringLiteral("selected"));
    all.selectedExpression = QRegularExpression(QStringLiteral("selected"));
    require(secretLeakAllowlistExcludes(selected, raw, line, url, {all}),
            "AND excludes only after all three native gates match");

    SecretLeakAllowlistEntry emptyAnd = entry(QStringLiteral("AND"));
    require(!secretLeakAllowlistExcludes(selected, raw, line, url, {emptyAnd}),
            "AND with empty path list takes native early false path");

    SecretLeakAllowlistEntry firstFailsAnd = entry(QStringLiteral("AND"));
    firstFailsAnd.pathExpressions << QRegularExpression(QStringLiteral("example"));
    firstFailsAnd.targetExpressions << QRegularExpression(QStringLiteral("miss"))
                                    << QRegularExpression(QStringLiteral("selected"));
    firstFailsAnd.selectedExpression = QRegularExpression(QStringLiteral("selected"));
    require(!secretLeakAllowlistExcludes(selected, raw, line, url, {firstFailsAnd}),
            "AND returns false at first failed target expression");
    return 0;
}
