#include "crawler.h"
#include "scanconfig.h"
#include "scanner.h"

#include <QCoreApplication>
#include <QFutureWatcher>
#include <QNetworkRequest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryFile>
#include <QTimer>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    // gui.exe:0x14011CE00 / 0x14011DBA0: false preserves the constructor's
    // -1 depth sentinel, while numeric zero disables the Scanner crawler.
    const ScanConfig booleanDepth = ScanConfig::fromJson(
        {{QStringLiteral("crawler"),
          QJsonObject{{QStringLiteral("depth"), QJsonValue(false)}}}});
    const ScanConfig zeroDepth = ScanConfig::fromJson(
        {{QStringLiteral("crawler"),
          QJsonObject{{QStringLiteral("depth"), QJsonValue(0.0)}}}});
    const ScanConfig numericDepth = ScanConfig::fromJson(
        {{QStringLiteral("crawler"),
          QJsonObject{{QStringLiteral("depth"), QJsonValue(3.0)}}}});
    if (booleanDepth.crawlerDepth() != -1 || !booleanDepth.crawlerEnabled()
        || zeroDepth.crawlerDepth() != 0 || zeroDepth.crawlerEnabled()
        || numericDepth.crawlerDepth() != 3 || !numericDepth.crawlerEnabled())
        return 6;

    // gui.exe:0x14011DC0D-0x14011DE09: scripts remain ordered and a positive
    // decimal-string cpuThreads is the only value that replaces -1.
    const ScanConfig testSelection = ScanConfig::fromJson(
        {{QStringLiteral("tests"), QJsonObject{
            {QStringLiteral("scripts"), QJsonArray{
                QStringLiteral("first"), QJsonValue(7.0), QStringLiteral("last")}},
            {QStringLiteral("cpuThreads"), QStringLiteral("3")}}}});
    const ScanConfig invalidCpuThreads = ScanConfig::fromJson(
        {{QStringLiteral("tests"), QJsonObject{
            {QStringLiteral("cpuThreads"), QStringLiteral("0")}}}});
    if (testSelection.testScripts() != QStringList{
            QStringLiteral("first"), QString(), QStringLiteral("last")}
        || testSelection.cpuThreads() != 3 || invalidCpuThreads.cpuThreads() != -1)
        return 24;

    // gui.exe:0x1400E8680 / 0x14013ED60: response routing is controlled by
    // the bit field at request attribute 1011, scope and 4xx/5xx status.
    const auto routedResponse = QSharedPointer<HttpResponse>::create();
    routedResponse->statusCode = 201;
    routedResponse->request.setAttribute(
        static_cast<QNetworkRequest::Attribute>(1011), 1 | 8 | 16 | 1024);
    const Scanner::ResponseRoutingDecision allRoutes =
        Scanner::responseRoutingDecision(Scanner::Scanning, routedResponse, true);
    if (!allRoutes.scriptTriggerEvent4 || !allRoutes.scriptTriggerEvent8
        || !allRoutes.manipulator)
        return 12;
    routedResponse->statusCode = 404;
    routedResponse->request.setAttribute(
        static_cast<QNetworkRequest::Attribute>(1011), 1024);
    const Scanner::ResponseRoutingDecision rejectedServerError =
        Scanner::responseRoutingDecision(Scanner::Scanning, routedResponse, true);
    if (rejectedServerError.scriptTriggerEvent4
        || rejectedServerError.scriptTriggerEvent8 || rejectedServerError.manipulator)
        return 13;
    routedResponse->request.setAttribute(
        static_cast<QNetworkRequest::Attribute>(1011), 16);
    if (!Scanner::responseRoutingDecision(Scanner::Scanning, routedResponse, true)
             .manipulator)
        return 15;
    const Scanner::ResponseRoutingDecision stoppedRoute =
        Scanner::responseRoutingDecision(Scanner::Stopping, routedResponse, true);
    if (stoppedRoute.scriptTriggerEvent4 || stoppedRoute.scriptTriggerEvent8
        || stoppedRoute.manipulator)
        return 14;

    // gui.exe:0x14011DE85-0x14011E875 and 0x1400E3120: crawler rules are
    // parsed from the configuration and applied to FileList before targets.
    const QJsonObject constrainedCrawler{
        {QStringLiteral("scope"), QJsonObject{
            {QStringLiteral("type"), QStringLiteral("manual")},
            {QStringLiteral("regex"), QStringLiteral("^https://allowed\\.invalid/")}}},
        {QStringLiteral("count"), 1},
        {QStringLiteral("depth"), 2},
        {QStringLiteral("fileExclusion"), QStringLiteral("*.PNG, [year]")},
        {QStringLiteral("urlExclusion"), QJsonArray{QStringLiteral("*private*")}}};
    const QJsonObject constrainedTarget{
        {QStringLiteral("items"), QJsonArray{QJsonObject{
            {QStringLiteral("type"), QStringLiteral("url")},
            {QStringLiteral("data"), QJsonArray{
                QStringLiteral("https://allowed.invalid/logo.png"),
                QStringLiteral("https://allowed.invalid/private")}}}}}};
    const ScanConfig fileListConfig = ScanConfig::fromJson(
        {{QStringLiteral("crawler"), constrainedCrawler},
         {QStringLiteral("http"), QJsonObject{{QStringLiteral("proxy"),
                                                 QJsonObject{{QStringLiteral("type"), QStringLiteral("noproxy")}}}}},
         {QStringLiteral("target"), constrainedTarget}});
    Scanner configuredScanner;
    configuredScanner.applyConfig(fileListConfig);
    const FileList &configuredFileList = configuredScanner.fileList();
    const QVariantMap configuredReasons = configuredFileList.skippedSummary()
                                             .value(QStringLiteral("reasons")).toMap();
    if (configuredFileList.field28 != 1 || configuredFileList.field30 != 2
        || !configuredFileList.matchesScope(QUrl(QStringLiteral("https://allowed.invalid/ok")))
        || configuredFileList.matchesScope(QUrl(QStringLiteral("https://other.invalid/ok")))
        || !configuredFileList.matchesScopeAndExclusions(
            QUrl(QStringLiteral("https://allowed.invalid/ok")))
        || configuredFileList.matchesScopeAndExclusions(
            QUrl(QStringLiteral("https://allowed.invalid/logo.png")))
        || configuredFileList.matchesScopeAndExclusions(
            QUrl(QStringLiteral("https://allowed.invalid/private")))
        || configuredFileList.size() != 0
        || configuredReasons.value(QStringLiteral("Excluded by filename rule")).toUInt() != 1
        || configuredReasons.value(QStringLiteral("URL limit reached")).toUInt() != 1)
        return 16;

    // gui.exe:0x14011F1EA-0x14011FFCF and 0x140132B00/0x140132AC0.
    const ScanConfig networkConfig = ScanConfig::fromJson(QJsonObject{
        {QStringLiteral("http"), QJsonObject{
            {QStringLiteral("maxParallelRequests"), 0},
            {QStringLiteral("timeout"), 2000},
            {QStringLiteral("userAgent"), QStringLiteral("Native-Reconstruction/1.0")},
            {QStringLiteral("headers"), QJsonArray{QJsonObject{
                {QStringLiteral("name"), QStringLiteral("X-Recovered")},
                {QStringLiteral("value"), QStringLiteral("yes")}}}},
            {QStringLiteral("proxy"), QJsonObject{
                {QStringLiteral("type"), QStringLiteral("noproxy")}}},
            {QStringLiteral("cookies"), QJsonArray{QJsonObject{
                {QStringLiteral("name"), QStringLiteral("native")},
                {QStringLiteral("value"), QStringLiteral("cookie")},
                {QStringLiteral("domain"), QStringLiteral("127.0.0.1")},
                {QStringLiteral("path"), QStringLiteral("/")}}
            }}
        }},
        {QStringLiteral("authentication"), QJsonObject{
            {QStringLiteral("http"), QJsonArray{QJsonObject{
                {QStringLiteral("enabled"), true},
                {QStringLiteral("user"), QStringLiteral("native-user")},
                {QStringLiteral("pass"), QStringLiteral("native-pass")}
            }}}
        }}
    });
    Scanner configuredNetworkScanner;
    configuredNetworkScanner.applyConfig(networkConfig);
    NetworkManager directManager{QString()};
    directManager.setConcurrentLimit(static_cast<qint32>(networkConfig.maxParallelRequests()));
    directManager.setAuthenticationCredentials(networkConfig.authenticationUser(),
                                               networkConfig.authenticationPassword());
    directManager.setTransferTimeout(networkConfig.httpTimeout());
    directManager.setUserAgent(networkConfig.userAgent());
    directManager.setDefaultHeaders(networkConfig.httpHeaders());
    directManager.setProxy(networkConfig.networkProxy());
    directManager.setCookies(networkConfig.httpCookies());
    if (networkConfig.maxParallelRequests() != 0 || directManager.concurrentLimit() != 1)
        return 17;

    QTcpServer authenticationServer;
    if (!authenticationServer.listen(QHostAddress::LocalHost))
        return 18;
    int authenticationRequests = 0;
    QObject::connect(&authenticationServer, &QTcpServer::newConnection,
                     &authenticationServer, [&authenticationServer, &authenticationRequests] {
        QTcpSocket *socket = authenticationServer.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket,
                         [socket, &authenticationRequests] {
            if (!socket->canReadLine())
                return;
            ++authenticationRequests;
            const QByteArray request = socket->readAll();
            if (request.contains("authorization: Basic bmF0aXZlLXVzZXI6bmF0aXZlLXBhc3M=")) {
                socket->write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            } else {
                socket->write("HTTP/1.1 401 Unauthorized\r\n"
                              "WWW-Authenticate: Basic realm=\"test\"\r\n"
                              "Content-Length: 0\r\nConnection: close\r\n\r\n");
            }
            socket->disconnectFromHost();
        });
    });
    QNetworkRequest authenticationRequest(QUrl(
        QStringLiteral("http://127.0.0.1:%1/auth").arg(authenticationServer.serverPort())));
    QFutureWatcher<NetworkManager::ResponsePointer> authenticationWatcher;
    QObject::connect(&authenticationWatcher, &QFutureWatcherBase::finished, &application,
                     &QCoreApplication::quit);
    authenticationWatcher.setFuture(directManager.submit(
        authenticationRequest, QByteArrayLiteral("GET"), {}, 0, QVariant(), 0, 0));
    QTimer::singleShot(5000, &application, &QCoreApplication::quit);
    application.exec();
    if (!authenticationWatcher.isFinished() || authenticationWatcher.future().isCanceled()
        || authenticationWatcher.future().resultCount() != 1)
        return 19;
    if (authenticationWatcher.future().result()->statusCode != 200)
        return 20;
    if (authenticationRequests < 2)
        return 21;

    QTcpServer headersServer;
    if (!headersServer.listen(QHostAddress::LocalHost))
        return 22;
    QByteArray receivedHeaders;
    QObject::connect(&headersServer, &QTcpServer::newConnection, &headersServer,
                     [&headersServer, &receivedHeaders] {
        QTcpSocket *socket = headersServer.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket,
                         [socket, &receivedHeaders] {
            if (!socket->canReadLine())
                return;
            receivedHeaders = socket->readAll();
            socket->write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            socket->disconnectFromHost();
        });
    });
    QNetworkRequest headersRequest(QUrl(
        QStringLiteral("http://127.0.0.1:%1/headers").arg(headersServer.serverPort())));
    QFutureWatcher<NetworkManager::ResponsePointer> headersWatcher;
    QObject::connect(&headersWatcher, &QFutureWatcherBase::finished, &application,
                     &QCoreApplication::quit);
    headersWatcher.setFuture(directManager.submit(
        headersRequest, QByteArrayLiteral("GET"), {}, 0, QVariant(), 0, 0));
    QTimer::singleShot(5000, &application, &QCoreApplication::quit);
    application.exec();
    if (!headersWatcher.isFinished() || headersWatcher.future().isCanceled()
        || headersWatcher.future().resultCount() != 1
        || headersWatcher.future().result()->statusCode != 200
        || !receivedHeaders.toLower().contains("x-recovered: yes")
        || !receivedHeaders.contains("user-agent: Native-Reconstruction/1.0")
        || !receivedHeaders.toLower().contains("cookie: native=cookie"))
        return 23;

    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost))
        return 1;
    QObject::connect(&server, &QTcpServer::newConnection, &server, [&server] {
        QTcpSocket *socket = server.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket] {
            if (!socket->canReadLine())
                return;
            const QByteArray request = socket->readAll();
            if (!request.startsWith("GET /proof HTTP/1.1")
                && !request.startsWith("GET /crawler HTTP/1.1")
                && !request.startsWith("GET /config")
                && !request.startsWith("GET /file-path HTTP/1.1")
                && !request.startsWith("GET /file-content HTTP/1.1")
                && !request.startsWith("POST /raw HTTP/1.1")) {
                socket->disconnectFromHost();
                return;
            }
            socket->write("HTTP/1.1 201 Created\r\nX-Proof: present\r\n"
                          "Content-Length: 2\r\n\r\nok");
            socket->disconnectFromHost();
        });
    });

    NetworkManager manager{QString()};
    int finishedSignals = 0;
    int allFinishedSignals = 0;
    QObject::connect(&manager, &NetworkManager::finished, &application,
                     [&] { ++finishedSignals; });
    QObject::connect(&manager, &NetworkManager::allFinished, &application,
                     [&] { ++allFinishedSignals; });
    QNetworkRequest request(QUrl(QStringLiteral("http://127.0.0.1:%1/proof")
                                     .arg(server.serverPort())));
    QFutureWatcher<NetworkManager::ResponsePointer> watcher;
    QObject::connect(&watcher, &QFutureWatcherBase::finished, &application,
                     &QCoreApplication::quit);
    watcher.setFuture(manager.submit(request, QByteArrayLiteral("GET"), {}, 0,
                                     QVariant(), 0, 0));
    QTimer::singleShot(5000, &application, &QCoreApplication::quit);
    application.exec();

    if (!watcher.isFinished() || watcher.future().isCanceled()
        || watcher.future().resultCount() != 1)
        return 2;
    const NetworkManager::ResponsePointer response = watcher.result();
    if (!response || response->statusCode != 201 || response->field120.size() != 2
        || response->raw.mid(response->bodyOffset, response->bodyLength) != "ok")
        return 3;

    // gui.exe:0x14011C0A0 / 0x14010F6B0: FileList slice, crawler request
    // construction, future submission and submitted/crawled counters.
    FileList fileList;
    const auto item = QSharedPointer<urlItem>::create(
        QStringLiteral("http://127.0.0.1:%1/crawler").arg(server.serverPort()),
        1, QByteArray());
    if (fileList.add(item, 0) != 1)
        return 4;
    Crawler crawler(&fileList, &manager);
    crawler.start();
    QTimer pollingTimer;
    pollingTimer.setInterval(5);
    QObject::connect(&pollingTimer, &QTimer::timeout, &application, [&] {
        if (manager.isIdle())
            application.quit();
    });
    pollingTimer.start();
    QTimer::singleShot(5000, &application, &QCoreApplication::quit);
    application.exec();
    if (crawler.scheduled() != 1 || crawler.crawled() != 1 || !item->field94
        || manager.totalRequests() != 2 || manager.completedRequests() != 2
        || finishedSignals != 2 || allFinishedSignals != 2)
        return 5;
    pollingTimer.stop();

    // gui.exe:0x140031910/0x140032070/0x140030EF0/0x140031150 and
    // 0x140122140: URL, file and raw HTTP TargetItems become urlItems before
    // 0x1400E2DA0 inserts them with the full FileList validation flags.
    QTemporaryFile targetFile;
    if (!targetFile.open())
        return 9;
    const QByteArray filePathUrl = QStringLiteral("http://127.0.0.1:%1/file-path\n")
                                      .arg(server.serverPort()).toUtf8();
    if (targetFile.write(filePathUrl) != filePathUrl.size() || !targetFile.flush())
        return 10;

    QJsonArray configItems;
    for (int index = 0; index < 6; ++index) {
        configItems.append(QJsonObject{
            {QStringLiteral("type"), QStringLiteral("url")},
            {QStringLiteral("data"),
             QStringLiteral("http://127.0.0.1:%1/config%2")
                 .arg(server.serverPort())
                 .arg(index)}});
    }
    configItems.append(QJsonObject{
        {QStringLiteral("type"), QStringLiteral("file")},
        {QStringLiteral("data"), QJsonObject{
            {QStringLiteral("name"), QStringLiteral("local target list")},
            {QStringLiteral("path"), targetFile.fileName()},
            {QStringLiteral("content"),
             QStringLiteral("http://127.0.0.1:%1/file-content\n")
                 .arg(server.serverPort())}}}});
    configItems.append(QJsonObject{
        {QStringLiteral("type"), QStringLiteral("http")},
        {QStringLiteral("data"), QJsonObject{
            {QStringLiteral("url"),
             QStringLiteral("http://127.0.0.1:%1/raw").arg(server.serverPort())},
            {QStringLiteral("method"), QStringLiteral("POST")},
            {QStringLiteral("body"), QStringLiteral("proof=raw")},
            {QStringLiteral("headers"), QJsonArray{QJsonObject{
                {QStringLiteral("name"), QStringLiteral("X-Raw-Proof")},
                {QStringLiteral("value"), QStringLiteral("present")}}}}}}});
    const ScanConfig scanConfig = ScanConfig::fromJson({
        {QStringLiteral("target"),
         QJsonObject{{QStringLiteral("items"), configItems}}},
        {QStringLiteral("crawler"),
         QJsonObject{{QStringLiteral("depth"), QJsonValue(false)}}},
        {QStringLiteral("http"), QJsonObject{{QStringLiteral("proxy"),
                                                QJsonObject{{QStringLiteral("type"), QStringLiteral("noproxy")}}}}}
    });
    const QList<QSharedPointer<urlItem>> targetSeeds = scanConfig.initialRequestItems();
    if (targetSeeds.size() != 8)
        return 11;
    FileList seedValidation;
    for (qsizetype index = 0; index < targetSeeds.size(); ++index) {
        if (seedValidation.add(targetSeeds.at(index), 0xff) == 0)
            return 20 + static_cast<int>(index);
    }
    Scanner scanner;
    bool scanFinished = false;
    QObject::connect(&scanner, &Scanner::finished, &application, [&] {
        scanFinished = true;
        application.quit();
    });
    scanner.applyConfig(scanConfig);
    if (scanner.fileList().size() != 8)
        return 7;
    scanner.start();
    QTimer::singleShot(5000, &application, &QCoreApplication::quit);
    application.exec();
    if (!scanFinished || scanner.crawler().scheduled() != 8
        || scanner.crawler().crawled() != 8)
        return 8;
    return 0;
}
