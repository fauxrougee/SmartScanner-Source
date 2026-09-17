#include "scanconfig.h"
#include "scanner.h"
#include "clireport.h"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QLoggingCategory>
#include <QMutex>
#include <cstdio>
#include <QJsonObject>
#include <QRegularExpression>
#include <QTextStream>
#include <QUrl>

namespace {
QCommandLineOption option(const QStringList &names, const QString &description,
                          const QString &valueName = {}) {
    return {names, description, valueName};
}

QString publishedHelp(const QCoreApplication &app) {
    return QStringLiteral(
        "Usage: %1 [options] [targets...]\n\n"
        "Options:\n"
        "  -u, --url <URL>            Target URL to scan (e.g., https://example.com)\n"
        "                             Can be used multiple times\n\n"
        "  -c, --config <FILE>        Scan config file\n"
        "  -f, --file <FILE>          Load list of target URLs from a file (one per\n"
        "                             line)\n\n"
        "  -o, --output <file>        Specify the full file name (including path) to\n"
        "                             save the JSON report.\n\n"
        "  --auth-basic <user:pass>   Use HTTP Basic Authentication. Specify username\n"
        "                             and password inline.\n"
        "                             Example: --auth-basic admin:securepassword\n\n"
        "  --proxy <proxy_url>        Use the specified proxy server for all requests.\n"
        "                             Example: --proxy http://proxy.example.com:8080\n"
        "                                     --proxy socks5://hostname:port\n\n"
        "  --proxy-auth <user:pass>   Specify proxy authentication credentials if\n"
        "                             required.\n"
        "                             Example: --proxy-auth admin:securepassword\n\n"
        "  --user-agent <ua_string>   Set a custom User-Agent string for all requests\n\n"
        "  --no-discovery             Do not even crawl input URLs. Alias for\n"
        "                             --crawl-depth 0\n"
        "  --no-follow                Only browse input URLs and Do not follow\n"
        "                             discovered links. Alias for --crawl-depth 1\n"
        "  -d, --crawl-depth <DEPTH>  Crawl depth (0 = no crawling at all, 1 = only\n"
        "                             fetch user input urls, 2+ = full crawl)\n"
        "  -s, --scope <REGEX>        Set a regex for URL scope\n"
        "  -t, --test <TESTS>         Test to perform\n"
        "                             Can be used multiple times\n\n"
        "  --exit-on <level>          Stop the scan immediately if an issue of the\n"
        "                             specified severity level is found.\n"
        "                             Allowed levels: \"informational\", \"low\", \"medium\",\n"
        "                             \"high\"\"), \"level\"\n"
        "                             Example: `--exit-on medium` will exit on medium or\n"
        "                             higher issues\n\n"
        "  -h, --help, -?             Displays help on commandline options\n\n"
        "  -v, --version              Displays version information\n\n\n"
        "Arguments:\n"
        "  targets...                 One or more target URLs (e.g.,\n"
        "                             https://example.com)\n"
        "                             If provided, it is equivalent to using `-u <URL>`\n")
        .arg(QDir::toNativeSeparators(app.applicationFilePath()));
}

int argumentError(const QString &message)
{
    QTextStream(stderr) << message << QStringLiteral(". Use -h argument to get help.")
                        << Qt::endl;
    return 2;
}

QJsonObject httpAuthentication(const QString &credentials)
{
    // sms.exe:0x14001F85D-0x14001F8C9: QString::section(':', 0, 0) and
    // section(':', 1, 1), then two ScanConfig setters.
    return {{QStringLiteral("http"), QJsonArray{QJsonObject{
        {QStringLiteral("enabled"), true},
        {QStringLiteral("user"), credentials.section(u':', 0, 0)},
        {QStringLiteral("pass"), credentials.section(u':', 1, 1)},
    }}}};
}

void removeCrawlerParserForLimitedDepth(QJsonObject &json)
{
    // sms.exe:0x14001F33C-0x14001F591. This adjustment happens before the
    // explicit -t/--test option is handled, so explicit tests replace it.
    QJsonObject tests = json.value(QStringLiteral("tests")).toObject();
    QJsonArray scripts = tests.value(QStringLiteral("scripts")).toArray();
    auto removeFirst = [&scripts](const QString &name) {
        for (qsizetype index = 0; index < scripts.size(); ++index) {
            if (scripts.at(index).toString() == name) {
                scripts.removeAt(index);
                return true;
            }
        }
        return false;
    };
    if (removeFirst(QStringLiteral("parser@o=crawler,dirRoot"))
        || removeFirst(QStringLiteral("parser@o=dirRoot,crawler"))) {
        scripts.append(QStringLiteral("parser@o=dirRoot"));
    }
    removeFirst(QStringLiteral("parser@o=crawler"));
    tests.insert(QStringLiteral("scripts"), scripts);
    json.insert(QStringLiteral("tests"), tests);
}
}

int main(int argc, char *argv[]) {
    QCoreApplication::setOrganizationName(QStringLiteral("TheSmartScanner"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("thesmartscanner.com"));
    QCoreApplication::setApplicationName(QStringLiteral("SmartScanner"));
    QCoreApplication::setApplicationVersion(QStringLiteral("3.0.0"));
    QCoreApplication app(argc, argv);
    Q_INIT_RESOURCE(sms_resources);
    // sms.exe:0x140022200 first statement.
    QLoggingCategory::setFilterRules(QStringLiteral(
        "*=false\nscanner=true\nscanner.*=true\n*.debug=false\nscanner.issues=false\n"));
    // sms.exe:0x140017220 installs 0x14001E1B0, whose signal slot
    // 0x14001D970 prints the message as "%s\n" to stdout under a mutex.
    qInstallMessageHandler([](QtMsgType, const QMessageLogContext &, const QString &message) {
        static QMutex mutex;
        const QMutexLocker locker(&mutex);
        fprintf(stdout, "%s\n", message.toUtf8().constData());
        fflush(stdout);
    });
    QCommandLineParser parser;
    parser.setSingleDashWordOptionMode(QCommandLineParser::ParseAsLongOptions);

    // This public option inventory, ordering, value names and descriptions are
    // verified against sms.exe --help (SmartScanner 3.0.0).
    const auto url = option({"u", "url"}, "Target URL to scan (e.g., https://example.com)\nCan be used multiple times", "URL");
    const auto config = option({"c", "config"}, "Scan config file", "FILE");
    const auto file = option({"f", "file"}, "Load list of target URLs from a file (one per line)", "FILE");
    const auto output = option({"o", "output"}, "Specify the full file name (including path) to\nsave the JSON report.", "file");
    const auto authBasic = option({"auth-basic"}, "Use HTTP Basic Authentication. Specify username\nand password inline.\nExample: --auth-basic admin:securepassword", "user:pass");
    const auto proxy = option({"proxy"}, "Use the specified proxy server for all requests.\nExample: --proxy http://proxy.example.com:8080\n         --proxy socks5://hostname:port", "proxy_url");
    const auto proxyAuth = option({"proxy-auth"}, "Specify proxy authentication credentials if\nrequired.\nExample: --proxy-auth admin:securepassword", "user:pass");
    const auto userAgent = option({"user-agent"}, "Set a custom User-Agent string for all requests", "ua_string");
    const auto noDiscovery = option({"no-discovery"}, "Do not even crawl input URLs. Alias for\n--crawl-depth 0");
    const auto noFollow = option({"no-follow"}, "Only browse input URLs and Do not follow\ndiscovered links. Alias for --crawl-depth 1");
    const auto crawlDepth = option({"d", "crawl-depth"}, "Crawl depth (0 = no crawling at all, 1 = only\nfetch user input urls, 2+ = full crawl)", "DEPTH");
    const auto scope = option({"s", "scope"}, "Set a regex for URL scope", "REGEX");
    const auto test = option({"t", "test"}, "Test to perform\nCan be used multiple times", "TESTS");
    const auto exitOn = option({"exit-on"}, "Stop the scan immediately if an issue of the\nspecified severity level is found.\nAllowed levels: \"informational\", \"low\", \"medium\",\n\"high\"\"), \"level\"\nExample: `--exit-on medium` will exit on medium or\nhigher issues", "level");
    for (const auto &value : {url, config, file, output, authBasic, proxy, proxyAuth, userAgent,
                              noDiscovery, noFollow, crawlDepth, scope, test, exitOn}) {
        parser.addOption(value);
    }
    const auto help = option({"h", "help", "?"}, "Displays help on commandline options");
    const auto version = option({"v", "version"}, "Displays version information");
    parser.addOption(help);
    parser.addOption(version);
    parser.addPositionalArgument(QStringLiteral("targets..."),
                                 QStringLiteral("One or more target URLs (e.g.,\nhttps://example.com)\nIf provided, it is equivalent to using `-u <URL>`"));
    if (!parser.parse(app.arguments())) {
        QTextStream(stderr) << parser.errorText() << Qt::endl;
        return 2;
    }
    if (parser.isSet(help)) {
        QTextStream(stdout) << publishedHelp(app);
        return 0;
    }
    if (parser.isSet(version)) {
        QTextStream(stdout) << QStringLiteral("SmartScanner 3.0.0") << Qt::endl;
        return 0;
    }

    const auto asset = QCoreApplication::applicationDirPath()
                       + QStringLiteral("/assets/default-scan-config.json");
    QString error;
    const auto configPath = parser.isSet(config) ? parser.value(config) : asset;
    auto scanConfig = ScanConfig::loadFile(configPath, &error);
    if (!error.isEmpty()) {
        QTextStream(stderr) << error << Qt::endl;
        return 2; // observed bootstrap exception exit code
    }

    auto json = scanConfig.json();
    auto targets = parser.values(url);
    targets.append(parser.positionalArguments());
    if (parser.isSet(file)) {
        QFile input(parser.value(file));
        if (!input.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream(stderr) << input.errorString() << Qt::endl;
            return 2;
        }
        while (!input.atEnd()) {
            const auto target = QString::fromUtf8(input.readLine()).trimmed();
            if (!target.isEmpty()) targets.append(target);
        }
    }
    if (!targets.isEmpty()) {
        QJsonArray items;
        for (const auto &target : targets) {
            items.append(QJsonObject{{QStringLiteral("type"), QStringLiteral("url")},
                                     {QStringLiteral("data"), target}});
        }
        // Exact shape from the extracted GUI's H8::compile(): `r.target =
        // e.target`; its initial target is {title:"target",items:[...]}. 
        json.insert(QStringLiteral("target"), QJsonObject{
            {QStringLiteral("title"), QStringLiteral("target")},
            {QStringLiteral("items"), items}
        });
    }
    auto http = json.value(QStringLiteral("http")).toObject();
    if (parser.isSet(proxy)) {
        // sms.exe:0x14001EBC3-0x14001EDA4. Only exact `http` and `socks`
        // schemes with a specified port are accepted by the native CLI.
        const QUrl proxyUrl = QUrl::fromUserInput(parser.value(proxy));
        if (!proxyUrl.isValid() || proxyUrl.port(-1) == -1
            || (proxyUrl.scheme() != QStringLiteral("http")
                && proxyUrl.scheme() != QStringLiteral("socks"))) {
            return argumentError(QStringLiteral("Invalid proxy URL provided"));
        }
        // Root-level `proxy` (ScanConfig parser reads json.proxy).
        QJsonObject proxyJson = json.value(QStringLiteral("proxy")).toObject();
        proxyJson.insert(QStringLiteral("type"), proxyUrl.scheme());
        proxyJson.insert(QStringLiteral("host"), proxyUrl.host());
        proxyJson.insert(QStringLiteral("port"), proxyUrl.port());
        json.insert(QStringLiteral("proxy"), proxyJson);
    }
    if (parser.isSet(proxyAuth)) {
        const QString credentials = parser.value(proxyAuth);
        if (!credentials.contains(u':'))
            return argumentError(QStringLiteral("Invalid proxy authentication provided"));
        QJsonObject proxyJson = json.value(QStringLiteral("proxy")).toObject();
        proxyJson.insert(QStringLiteral("user"), credentials.section(u':', 0, 0));
        proxyJson.insert(QStringLiteral("pass"), credentials.section(u':', 1, 1));
        json.insert(QStringLiteral("proxy"), proxyJson);
    }
    if (parser.isSet(userAgent)) {
        const QString value = parser.value(userAgent);
        if (value.isEmpty())
            return argumentError(QStringLiteral("User agent cannot be empty"));
        http.insert(QStringLiteral("userAgent"), value);
    }
    json.insert(QStringLiteral("http"), http);

    if (parser.isSet(authBasic)) {
        const QString credentials = parser.value(authBasic);
        if (!credentials.contains(u':'))
            return argumentError(QStringLiteral("Invalid HTTP Basic authentication provided"));
        json.insert(QStringLiteral("authentication"), httpAuthentication(credentials));
    }

    int depth = parser.isSet(noFollow) ? 1 : (parser.isSet(noDiscovery) ? 0 : -1);
    if (parser.isSet(crawlDepth)) {
        bool ok = false;
        depth = parser.value(crawlDepth).toInt(&ok, 10);
        if (!ok || depth < 0)
            return argumentError(QStringLiteral("Crawl depth should be 0 or a greater number"));
    }
    if (depth <= 1)
        removeCrawlerParserForLimitedDepth(json);
    if (parser.isSet(crawlDepth) || parser.isSet(noDiscovery) || parser.isSet(noFollow)) {
        QJsonObject crawler = json.value(QStringLiteral("crawler")).toObject();
        crawler.insert(QStringLiteral("depth"), depth);
        json.insert(QStringLiteral("crawler"), crawler);
    }

    if (parser.isSet(test)) {
        QJsonObject tests = json.value(QStringLiteral("tests")).toObject();
        QJsonArray scripts;
        for (const QString &script : parser.values(test))
            scripts.append(script);
        tests.insert(QStringLiteral("scripts"), scripts);
        json.insert(QStringLiteral("tests"), tests);
    }
    if (parser.isSet(scope)) {
        const QRegularExpression expression(parser.value(scope),
                                            QRegularExpression::CaseInsensitiveOption);
        if (!expression.isValid())
            return argumentError(QStringLiteral("Scopre regex error: %1")
                                     .arg(expression.errorString()));
        QJsonObject crawler = json.value(QStringLiteral("crawler")).toObject();
        crawler.insert(QStringLiteral("scope"), QJsonObject{
            {QStringLiteral("type"), QStringLiteral("manual")},
            {QStringLiteral("regex"), parser.value(scope)},
        });
        json.insert(QStringLiteral("crawler"), crawler);
    }
    if (parser.isSet(output) && parser.value(output).isEmpty())
        return argumentError(QStringLiteral("Report file name cannot be empty"));
    if (parser.isSet(exitOn)) {
        const QString severity = parser.value(exitOn).toLower();
        if (severity != QStringLiteral("informational") && severity != QStringLiteral("low")
            && severity != QStringLiteral("medium") && severity != QStringLiteral("high")) {
            return argumentError(QStringLiteral("Invalid severity provided for exit-on option"));
        }
    }
    scanConfig = ScanConfig::fromJson(json);

    // sms.exe validates before entering QApplication::exec(); this exact CLI
    // suffix is not part of the generic ScanConfig validation API used by GUI.
    if (!scanConfig.isValid(&error)) {
        QTextStream(stderr) << error << QStringLiteral(". Use -h argument to get help.") << Qt::endl;
        return 2;
    }

    int exitOnSeverity = 0;
    if (parser.isSet(exitOn)) {
        // sms.exe:0x14001FA62-0x14001FB08. Values are intentionally reverse
        // ordered, because lower numeric values mean a more serious issue.
        const QString severity = parser.value(exitOn).toLower();
        if (severity == QStringLiteral("informational")) exitOnSeverity = 4;
        else if (severity == QStringLiteral("low")) exitOnSeverity = 3;
        else if (severity == QStringLiteral("medium")) exitOnSeverity = 2;
        else exitOnSeverity = 1;
    }

    Scanner scanner;
    QObject::connect(&scanner, &Scanner::log, [](int, const QString &, const QString &message) {
        QTextStream(stderr) << message << Qt::endl;
    });
    QObject::connect(&scanner.issueDb(), &IssueDb::newIssueAdded, &scanner,
                     [&scanner, exitOnSeverity](const Issue &issue) {
        // sms.exe:0x14001DF50 writes this exact record before evaluating the
        // stop predicate. Severity text is from 0x14001D820.
        QString severity;
        switch (issue.field38) {
        case 1: severity = QStringLiteral("High"); break;
        case 2: severity = QStringLiteral("Medium"); break;
        case 3: severity = QStringLiteral("Low"); break;
        case 4: severity = QStringLiteral("Information"); break;
        default: severity = QStringLiteral("Unknown"); break;
        }
        // sms.exe:0x14001DF50: %1 = name (+24), %2 = severity, %3 = url.
        QTextStream(stdout) << QStringLiteral("[%1] [%2] - %3\n")
                                  .arg(issue.field18, severity,
                                       issue.field30.toString());
        if (exitOnSeverity != 0 && issue.field38 <= exitOnSeverity)
            QTextStream(stdout) << QStringLiteral("Stopping scan due to --exit-on ...\n");
        if (exitOnSeverity != 0 && issue.field38 <= exitOnSeverity)
            scanner.stop();
    });
    QObject::connect(&scanner, &Scanner::finished, &app,
                     [&app, &parser, &output, &scanner, exitOnSeverity] {
        if (parser.isSet(output)) {
            QTextStream standardOut(stdout);
            QTextStream standardError(stderr);
            CliReport::write(parser.value(output), scanner, standardOut, standardError);
        }

        // Native exit-code test is an exact severity match, even though its
        // earlier stop predicate accepts every more-serious issue.
        bool exitWithIssue = false;
        if (exitOnSeverity != 0) {
            for (const Issue &issue : scanner.issueDb().issues()) {
                if (issue.field38 == exitOnSeverity) {
                    exitWithIssue = true;
                    break;
                }
            }
        }
        app.exit(exitWithIssue ? 1 : 0);
    });
    scanner.applyConfig(scanConfig);
    // sms.exe:0x1400225EC.
    QTextStream(stdout) << QStringLiteral("Scanning %1 ...\n").arg(scanner.reportTarget());
    scanner.start();
    if (scanner.status() == Scanner::Stopped) return 2;

    // The original stays in QApplication::exec() when scanning is active. The
    // reconstructed core currently has no recovered test engine to complete.
    return app.exec();
}
