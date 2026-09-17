#include "httpclient.h"
#include "issuedb.h"
#include "secretleakfinding.h"
#include "urlnormalizer.h"

#include <QCoreApplication>

#include <cstdlib>
#include <iostream>

// Offline trace of gui.exe:0x140045630 and the outer rule loop of
// gui.exe:0x140054490.  The rules below are synthetic fixtures, not
// Gitleaks rules from assets/scripts/secretleak/gitleaks.toml.

namespace {

void require(bool value, const char *message)
{
    if (!value) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

HttpResponse responseWithBody(const QByteArray &body)
{
    HttpResponse response;
    response.url = QUrl(QStringLiteral("https://user:pw@example.test:8443/dir/page?q=1#frag"));
    response.statusCode = 200;
    response.raw = QByteArrayLiteral("HTTP/1.1 200 OK\r\n\r\n");
    response.bodyOffset = response.raw.size();
    response.raw.append(body);
    response.bodyLength = body.size();
    return response;
}

SecretLeakCompiledRule rule(const QString &id, const QString &pattern)
{
    SecretLeakCompiledRule compiled;
    compiled.global.field0 = id;
    compiled.global.field24 = id + QStringLiteral(" description");
    compiled.global.expression = QRegularExpression(pattern);
    return compiled;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString catalogue = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();

    SecretLeakConfig config;
    config.rules.append(rule(QStringLiteral("first"), QStringLiteral("AKIA[0-9]{4}")));
    config.rules.append(rule(QStringLiteral("second"), QStringLiteral("tok_([a-z]+)")));

    // Outer loop: records follow rule order, then match order within a rule.
    const QString body = QStringLiteral("tok_abc AKIA1234 AKIA5678");
    const QList<SecretLeakMatchRecord> records =
        secretLeakMatches(config, body, QStringLiteral("https://example.test/"));
    require(records.size() == 3, "outer loop must append records from every rule");
    require(records.at(0).field0 == QStringLiteral("first")
                && records.at(1).field0 == QStringLiteral("first")
                && records.at(2).field0 == QStringLiteral("second"),
            "records must follow native rule-vector order");
    require(records.at(2).selectedCapture == QStringLiteral("abc"),
            "first non-empty group must be selected");

    // The a1+24 global allowlist applies to every rule.
    SecretLeakConfig allowlisted = config;
    SecretLeakAllowlistEntry entry;
    entry.condition = QStringLiteral("OR");
    entry.selectedExpression = QRegularExpression(QStringLiteral("AKIA1234|abc"));
    allowlisted.globalAllowlist.append(entry);
    const QList<SecretLeakMatchRecord> filtered =
        secretLeakMatches(allowlisted, body, QStringLiteral("https://example.test/"));
    require(filtered.size() == 1 && filtered.first().selectedCapture == QStringLiteral("AKIA5678"),
            "global allowlist must filter records of all rules");

    // Response gates of 0x140045630.
    IssueDb gated;
    HttpResponse noStatus = responseWithBody("AKIA1234");
    noStatus.statusCode = 0;
    require(!secretLeakProcessResponse(&noStatus, &gated, config, catalogue),
            "status <= 0 must not create an issue");
    HttpResponse connectionError = responseWithBody("AKIA1234");
    connectionError.error = HttpResponse::ConnectionError;
    require(!secretLeakProcessResponse(&connectionError, &gated, config, catalogue),
            "state 1 must be rejected");
    HttpResponse timeout = responseWithBody("AKIA1234");
    timeout.error = HttpResponse::Timeout;
    require(!secretLeakProcessResponse(&timeout, &gated, config, catalogue),
            "state 5 must be rejected");
    HttpResponse clean = responseWithBody("nothing here");
    require(!secretLeakProcessResponse(&clean, &gated, config, catalogue),
            "no record must not create an issue");
    require(gated.issues().isEmpty(), "gated paths must not submit issues");

    // State 2 passes the native predicate; only the first record is reported.
    IssueDb db;
    HttpResponse leaking = responseWithBody("AKIA1234 AKIA5678 tok_abc");
    leaking.error = HttpResponse::InvalidStatusLine;
    require(secretLeakProcessResponse(&leaking, &db, config, catalogue),
            "matching response must create an issue");
    require(db.issues().size() == 1, "exactly one issue per response");
    Issue issue = db.issues().first();
    require(issue.field18 == QStringLiteral("Sensitive Data Disclosure"), "issue name");
    require(issue.field38 == 2, "severity/impact field must be 2");
    require(issue.field110 == 1, "field +0x110 must be 1");
    require(issue.field30 == QUrl(QStringLiteral("https://example.test:8443")),
            "issue URL must be toString(4326) of the response URL");
    require(issue.fieldF0.isEmpty(), "slot attaches no HTTP capture");
    const quint64 expected = qHash(
        QStringView(UrlNormalizer::canonical(leaking.url, 110) + QStringLiteral("AKIA1234")), 0);
    require(issue.field258 && issue.field250 == expected,
            "identity must hash canonical URL + first selected capture");

    // Same URL and first capture: identity duplicate is refused by IssueDb.
    require(secretLeakProcessResponse(&leaking, &db, config, catalogue),
            "slot submits even when IssueDb refuses the duplicate");
    require(db.issues().size() == 1, "duplicate identity must not be added twice");
    return 0;
}
