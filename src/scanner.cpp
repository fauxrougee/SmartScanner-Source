#include "scanner.h"
#include "httpheadercheck.h"
#include "passivechecks.h"
#include "crawlerhtmlparser.h"
#include "crawlerrequestitem.h"

#include <QCoreApplication>
#include <QJsonArray>
#include <QDate>
#include <QLoggingCategory>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSet>
#include <cstdio>

Scanner::Scanner(QObject *parent)
    : QObject(parent),
      m_id(QUuid::createUuid()),
      m_networkManager(m_id.toString(QUuid::WithoutBraces), this),
      m_fileList(this),
      m_issueDb(this),
      m_crawler(&m_fileList, &m_networkManager, this),
      m_manipulator(this),
      m_duration(this) {
    // gui.exe Scanner_ctor calls QUuid::createUuid and constructs its
    // NetworkManager at +0x28, FileList at +0x38, and IssueDb at +0x48.
    // gui.exe:0x1400E0202 -> 0x140113DC0. Observer is bounded by Scanner's
    // member lifetimes; native components use shared ownership instead.
    m_manipulator.networkManager = &m_networkManager;

    // Connect ScriptCatalog to IssueDb and NetworkManager for active tests
    m_scriptCatalog.setIssueDb(&m_issueDb);
    m_scriptCatalog.setNetworkManager(QSharedPointer<NetworkManager>(&m_networkManager, [](NetworkManager*){}));

    // Initialize ScriptRunner and ScriptTrigger for active tests
    m_scriptRunner = QSharedPointer<ScriptRunner>::create(m_scriptCatalog, 0, this);
    m_scriptTrigger = QSharedPointer<ScriptTrigger>::create(m_scriptRunner, m_scriptCatalog, this);

    connect(&m_networkManager, &NetworkManager::finished, this,
            &Scanner::requestFinished, Qt::QueuedConnection);
    connect(&m_networkManager, &NetworkManager::allFinished, this,
            &Scanner::continueScan, Qt::QueuedConnection);
    // Connect Manipulator to ScriptTrigger for active tests
    connect(&m_manipulator, &Manipulator::eventTriggered, this,
            [this](Event event, NetworkResponsePtr response, ParameterInjectionPtr parameter) {
                m_pendingScripts += m_scriptTrigger->emitEvent(event, response, parameter);
            });
    // Connect ScriptRunner finished signal
    connect(m_scriptRunner.data(), &ScriptRunner::finished, this, [this]() {
        --m_pendingScripts;
        QMetaObject::invokeMethod(this, "checkFinished", Qt::QueuedConnection);
    });
    // Connect IssueDb to forward issue updates to the UI
    connect(&m_issueDb, &IssueDb::newIssueAdded, this, [this](const Issue &) {
        emit issuesUpdated(issuesAsJson());
    });
    connect(&m_issueDb, &IssueDb::issueUpdated, this, [this]() {
        emit issuesUpdated(issuesAsJson());
    });
}

void Scanner::requestFinished(NetworkManager::ResponsePointer response)
{
    // gui.exe:0x1400E8680 first calls this Scanner work cycle before it
    // examines the reply. This is observable even when no route is eligible.
    continueScan();

    // The ScriptTrigger receiver remains incomplete. Manipulator now has the
    // native parameter factories; its downstream event receiver is pending.
    const bool withinScope = response && m_fileList.matchesScope(response->url);
    const ResponseRoutingDecision routing = responseRoutingDecision(
        m_status, response, withinScope);
    if (qEnvironmentVariableIsSet("SMS_TRACE") && response) {
        fprintf(stderr, "[trace] finished %s status=%d http=%d scope=%d e4=%d e8=%d m=%d attr=%d\n",
                qPrintable(response->url.toString()), int(m_status), response->statusCode,
                int(withinScope), int(routing.scriptTriggerEvent4),
                int(routing.scriptTriggerEvent8), int(routing.manipulator),
                response->request.attribute(static_cast<QNetworkRequest::Attribute>(1011)).toInt());
    }
    // Passive security tests that analyze HTTP responses.
    // The native ScriptRunner bridge remains unreconstructed, so tests are
    // routed directly by their factory key prefix.
    const QString genericIssues = QCoreApplication::applicationDirPath()
        + QStringLiteral("/assets/issues/generic-min.json");
    if (routing.scriptTriggerEvent8) {
      for (const QString &selection : m_config.testScripts()) {
        const QString testName = selection.section(QLatin1Char('@'), 0, 0);

        if (testName == QStringLiteral("httpheaders")) {
            HttpHeaderCheck::process(response, &m_issueDb, selection, genericIssues);
        } else if (testName == QStringLiteral("errordetection")) {
            PassiveChecks::processErrorDetection(response, &m_issueDb, genericIssues);
        } else if (testName == QStringLiteral("passive")) {
            PassiveChecks::processPassive(response, &m_issueDb, selection, genericIssues);
        } else if (testName == QStringLiteral("secretleak")) {
            PassiveChecks::processSecretLeak(response, &m_issueDb, genericIssues);
        } else if (testName == QStringLiteral("robotstxt")) {
            PassiveChecks::processRobotsTxt(response, &m_issueDb, genericIssues);
        } else if (testName == QStringLiteral("wploginpage")) {
            PassiveChecks::processLoginPage(response, &m_issueDb, genericIssues);
        } else if (testName == QStringLiteral("fingerprint")) {
            PassiveChecks::processFingerprint(response, &m_issueDb, genericIssues);
        } else if (testName == QStringLiteral("https")) {
            PassiveChecks::processHttps(response, &m_issueDb, selection, genericIssues);
        } else if (testName == QStringLiteral("httpsredirection")) {
            PassiveChecks::processHttpsRedirection(response, &m_issueDb, genericIssues);
        } else if (testName == QStringLiteral("passwordform")) {
            PassiveChecks::processLoginPage(response, &m_issueDb, genericIssues);
        }
      }
      // Always check for broken links (404 responses)
      PassiveChecks::processBrokenLink(response, &m_issueDb, genericIssues);
      // Check TLS version
      PassiveChecks::processTlsVersion(response, &m_issueDb, genericIssues);
    }

    // Emit script events for active tests via ScriptTrigger
    if (routing.scriptTriggerEvent4 || routing.scriptTriggerEvent8) {
        Event event;
        event.type = routing.scriptTriggerEvent8 ? 8 : 4;
        event.data = QVariant::fromValue(response->url);
        m_pendingScripts += m_scriptTrigger->emitEvent(event, response, {});
    }

    // HTML parsing and URL extraction for crawling
    // This is the reconstructed version of gui.exe's crawler URL extraction
    if (response && withinScope && m_crawlerEnabled && m_status == Scanning) {
        // Get Content-Type header from field120 (HeaderRange pairs)
        QByteArray contentType;
        for (const HttpResponse::HeaderRange &range : response->field120) {
            const QByteArray headerName = response->raw.mid(range.name.offset, range.name.length);
            if (headerName.compare(QByteArrayLiteral("content-type"), Qt::CaseInsensitive) == 0) {
                contentType = response->raw.mid(range.value.offset, range.value.length);
                break;
            }
        }

        if (crawlerAcceptsContentType(contentType)) {
            // Get body from raw data using bodyOffset and bodyLength
            const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
            const QString document = QString::fromUtf8(body);
            const QUrl baseUrl = response->url;
            const qint32 attr1004 = response->request.attribute(
                static_cast<QNetworkRequest::Attribute>(1004)).toInt();
            const qint32 attr1011 = response->request.attribute(
                static_cast<QNetworkRequest::Attribute>(1011)).toInt();
            const qint64 attr1012 = response->request.attribute(
                static_cast<QNetworkRequest::Attribute>(1012)).toLongLong();

            // Extract href links
            for (const QUrl &location : crawlerHtmlHrefLocations(baseUrl, document)) {
                if (m_fileList.matchesScope(location)) {
                    auto item = makeCrawlerRequest(location, baseUrl, attr1004, 1, attr1011, attr1012);
                    m_fileList.add(item, 0x01);
                }
            }

            // Extract src links (images, scripts, etc.)
            for (const QUrl &location : crawlerHtmlSourceLocations(baseUrl, document)) {
                if (m_fileList.matchesScope(location)) {
                    auto item = makeCrawlerRequest(location, baseUrl, attr1004, 1, attr1011, attr1012);
                    m_fileList.add(item, 0x01);
                }
            }

            // Extract iframe sources
            for (const QUrl &location : crawlerHtmlIframeLocations(baseUrl, document)) {
                if (m_fileList.matchesScope(location)) {
                    auto item = makeCrawlerRequest(location, baseUrl, attr1004, 1, attr1011, attr1012);
                    m_fileList.add(item, 0x01);
                }
            }

            // Extract meta refresh URLs
            for (const QUrl &location : crawlerMetaRefreshLocations(baseUrl, document)) {
                if (m_fileList.matchesScope(location)) {
                    auto item = makeCrawlerRequest(location, baseUrl, attr1004, 1, attr1011, attr1012);
                    m_fileList.add(item, 0x01);
                }
            }
        }
    }

    // gui.exe:0x1400E88C5, after the event8 route, independent of its eligibility.
    if (routing.manipulator)
        m_manipulator.scan(response);
}

Scanner::ResponseRoutingDecision Scanner::responseRoutingDecision(
    ScanStatus status, const NetworkManager::ResponsePointer &response,
    bool withinScope) noexcept
{
    // gui.exe:0x1400E8680. The unsigned status expression rejects exactly
    // Scanner states 3 (Stopping) and 4 (Stopped), then checks request
    // attribute 1011 through gui.exe:0x14013ED60.
    ResponseRoutingDecision decision;
    if (!response || status == Stopping || status == Stopped)
        return decision;

    const qint32 attributes = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    const bool request4 = (attributes & 1) == 1;
    const bool request8 = (attributes & 8) == 8;
    const bool request16 = (attributes & 16) == 16;
    const bool request1024 = (attributes & 1024) == 1024;
    const bool serverError = (response->statusCode >= 400 && response->statusCode <= 499)
                          || (response->statusCode >= 500 && response->statusCode <= 599);

    decision.scriptTriggerEvent4 = request4;
    decision.scriptTriggerEvent8 = request8 && withinScope;
    decision.manipulator = (request16 || (request1024 && !serverError))
                         && withinScope;
    return decision;
}

void Scanner::applyConfig(const ScanConfig &config)
{
    // gui.exe:0x1400E8F20 copies ScanConfig, then 0x1400E3120 forwards its
    // fields to FileList, RequestManager, Crawler, ScriptRunner and the other
    // owned components. The latter objects are not all reconstructed yet.
    m_config = config;
    // gui.exe:0x1400E3120 applies these ScanConfig values to FileList before
    // creating target request items: its vtable slots 0/2/6 and list setters
    // feed the count, scope expression, depth, file exclusions and URL
    // exclusions respectively.

    // Generate auto scope if no manual scope is set
    QRegularExpression scopeExpr = m_config.scopeExpression();
    if (!scopeExpr.isValid() || scopeExpr.pattern().isEmpty()) {
        // Auto scope: generate from target URLs
        const QList<QUrl> urls = m_config.initialUrls();
        if (!urls.isEmpty()) {
            QStringList hostPatterns;
            QSet<QString> seenHosts;
            for (const QUrl &url : urls) {
                QString host = url.host().toLower();
                if (host.isEmpty() || seenHosts.contains(host))
                    continue;
                seenHosts.insert(host);
                // Escape special regex characters and create pattern
                QString escapedHost = QRegularExpression::escape(host);
                // Allow www. prefix optionally
                if (host.startsWith(QStringLiteral("www."))) {
                    escapedHost = QStringLiteral("(?:www\\.)?") + QRegularExpression::escape(host.mid(4));
                } else {
                    escapedHost = QStringLiteral("(?:www\\.)?") + escapedHost;
                }
                hostPatterns.append(escapedHost);
            }
            if (!hostPatterns.isEmpty()) {
                QString pattern = QStringLiteral("^https?://(?:") + hostPatterns.join(QLatin1Char('|'))
                                + QStringLiteral(")(?::\\d+)?(?:/|$)");
                scopeExpr = QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption);
            }
        }
    }
    m_fileList.field20 = scopeExpr;
    m_fileList.field28 = m_config.crawlerCount();
    m_fileList.field30 = m_config.crawlerDepth();
    m_fileList.field38 = m_config.fileExclusions();
    m_fileList.field98 = m_config.urlExclusions();
    // Set scope validator for NetworkManager to validate redirects
    m_networkManager.setScopeValidator([this](const QUrl &url) {
        return m_fileList.matchesScope(url);
    });
    // gui.exe:0x1400E3120 forwards these through NetworkManager setters
    // 0x140132B00 and 0x140132AC0.
    m_networkManager.setConcurrentLimit(
        static_cast<qint32>(m_config.maxParallelRequests()));
    m_networkManager.setAuthenticationCredentials(m_config.authenticationUser(),
                                                   m_config.authenticationPassword());
    m_networkManager.setTransferTimeout(m_config.httpTimeout());
    m_networkManager.setUserAgent(m_config.userAgent());
    m_networkManager.setDefaultHeaders(m_config.httpHeaders());
    m_networkManager.setProxy(m_config.networkProxy());
    m_networkManager.setCookies(m_config.httpCookies());
    // gui.exe:0x1400E3563/80 -> 0x140113DB0 / 0x140113D30.
    m_manipulator.vectorFlags = m_config.vectorFlags();
    m_manipulator.exclusions = m_config.parameterExclusions();
    // gui.exe:0x1400E3120 invokes ScanConfig's vtable slot +0x30 (the raw
    // crawler.depth field at +0x1B8) and stores `setnz` in Scanner +0x98.
    m_crawlerEnabled = m_config.crawlerEnabled();
    // gui.exe:0x1400E3120 -> 0x1400EA5B0 -> 0x14010FA20.
    m_crawler.setValueRules(m_config.valueRules());
    // Configure ScriptTrigger with test scripts from config
    m_scriptTrigger->setScripts(m_config.testScripts());

    // gui.exe:0x140121620 / 0x140122140 dispatches URL, file and raw HTTP
    // TargetItems to urlItem factories; 0x1400E2DA0 changes field60 to 1 and
    // inserts every result with flags 0xff.
    const QList<QSharedPointer<urlItem>> targetItems = m_config.initialRequestItems();
    if (targetItems.size() == 1) {
        // sms.exe:0x1401209E0 single-target branch (observed output: host).
        m_reportTarget = targetItems.constFirst()->url().host();
        if (m_reportTarget.isEmpty())
            m_reportTarget = targetItems.constFirst()->url().toString();
    } else if (targetItems.size() > 1) {
        m_reportTarget = QStringLiteral("%1 targets").arg(targetItems.size());
    } else {
        m_reportTarget.clear();
    }
    for (const QSharedPointer<urlItem> &item : targetItems) {
        item->field60 = 1;
        m_fileList.add(item, 0xff);
    }

    // Automatically add robots.txt for each target host
    QSet<QString> seenHosts;
    for (const QSharedPointer<urlItem> &item : targetItems) {
        const QString host = item->url().host().toLower();
        if (seenHosts.contains(host))
            continue;
        seenHosts.insert(host);

        QUrl robotsUrl;
        robotsUrl.setScheme(item->url().scheme());
        robotsUrl.setHost(item->url().host());
        if (item->url().port() != -1)
            robotsUrl.setPort(item->url().port());
        robotsUrl.setPath(QStringLiteral("/robots.txt"));

        auto robotsItem = QSharedPointer<urlItem>::create(
            robotsUrl.toString(), 1, QByteArray());
        robotsItem->field60 = 1;
        robotsItem->field6C = 1;
        m_fileList.add(robotsItem, 0x01);
    }
}

void Scanner::start() {
    // gui.exe:0x1400E9400: start has no ScanConfig parameter and enters only
    // from Idle or Paused.
    qDebug() << "Scanner::start() - current status:" << static_cast<int>(m_status);
    if (m_status != Idle && m_status != Paused)
        return;
    m_elapsed.restart();
    m_duration.start();
    setStatus(Scanning);
    // Start ScriptRunner to process active tests
    m_scriptRunner->start();
    // gui.exe:0x1400E9442 / 0x1400E9457.
    qDebug() << "Scanner::start() - crawlerEnabled:" << m_crawlerEnabled;
    qDebug() << "Scanner::start() - FileList size:" << m_fileList.size();
    if (m_crawlerEnabled)
        m_crawler.start();
}

qint64 Scanner::elapsedMilliseconds() const noexcept {
    return m_elapsed.isValid() ? m_elapsed.elapsed() : 0;
}

QVariantMap Scanner::updateValues() const
{
    // The native producer begins with FileList's eight counters, queue size,
    // and their sum. Its NetworkManager portion is direct fields: total,
    // total minus pending/active, and last URL. Crawler, ScriptRunner and
    // IssueDb producers remain intentionally absent.
    const QVariantMap skipped = m_fileList.skippedSummary();
    const qint64 skippedTotal = skipped.value(QStringLiteral("total")).toLongLong();
    const qint64 queued = m_fileList.size();
    return {
        {QStringLiteral("crawler_skipped"), skipped},
        {QStringLiteral("crawler_queued"), queued},
        {QStringLiteral("crawler_discovered"), skippedTotal + queued},
        {QStringLiteral("crawler_crawled"), m_crawler.crawled()},
        {QStringLiteral("request_total"), m_networkManager.totalRequests()},
        {QStringLiteral("request_completed"), m_networkManager.completedRequests()},
        {QStringLiteral("request_last"), m_networkManager.lastUrl()}
    };
}

void Scanner::stop() {
    // gui.exe:0x1400EA380 accepts Scanning, Pausing and Paused only.
    if (m_status != Scanning && m_status != Pausing && m_status != Paused)
        return;
    setStatus(Stopping);
    // gui.exe:0x1400EA3C4 calls the NetworkManager terminal cancellation
    // route before queueing this exact slot. ScriptRunner is still not a live
    // reconstructed worker, so its separate cancellation call is unbound.
    m_networkManager.stop();
    QMetaObject::invokeMethod(this, "checkFinished", Qt::QueuedConnection);
}

void Scanner::pause() {
    // gui.exe:0x1400E7310 does not call checkFinished directly.
    if (m_status != Scanning)
        return;
    setStatus(Pausing);
}

void Scanner::resume() {
    // gui.exe:0x1400E8EB0 accepts both Pausing and Paused.
    if (m_status != Pausing && m_status != Paused)
        return;
    m_duration.start();
    setStatus(Scanning);
    // gui.exe:0x1400E8EE8 / 0x1400E8EFD.
    if (m_crawlerEnabled)
        m_crawler.start();
}

void Scanner::checkFinished() {
    // Direct control flow of sms.exe Scanner_checkFinished (0x1400DBB30):
    // when both ScriptRunner and NetworkManager are empty, translate the
    // transitional state 1/3/5 to Finished/Stopped/Paused respectively.
    if (m_pendingScripts != 0 || m_pendingRequests != 0 || !m_networkManager.isIdle()) return;
    switch (m_status) {
    case Scanning: setStatus(Finished); break;
    case Stopping: setStatus(Stopped); break;
    case Pausing: setStatus(Paused); break;
    default: break;
    }
}

void Scanner::continueScan() {
    // gui.exe:0x1400E43C0, exposed as Scanner's Qt slot index 7 by
    // 0x1400EA760. The native starts another crawler slice only in Scanning
    // state and while the ScriptRunner range has fewer than 200 entries.
    if (m_crawlerEnabled && m_status == Scanning && m_pendingScripts < 200)
        m_crawler.start();

    // The same native work cycle queues checkFinished only once ScriptRunner
    // and NetworkManager both report no work.
    if (m_pendingScripts == 0 && m_pendingRequests == 0 && m_networkManager.isIdle())
        QMetaObject::invokeMethod(this, "checkFinished", Qt::QueuedConnection);
}

void Scanner::setStatus(ScanStatus next) {
    if (m_status == next) return;
    m_status = next;
    // sms.exe:0x1400E38B0: qCInfo(scanner category) status texts.
    {
        static const QLoggingCategory scannerLog("scanner");
        const char *text = nullptr;
        switch (next) {
        case Idle: text = "Scan status changed: Idle"; break;
        case Scanning: text = "Scan status changed: Scanning..."; break;
        case Finished: text = "Scan status changed: Finished"; break;
        case Stopping: text = "Scan status changed: Stopping..."; break;
        case Stopped: text = "Scan status changed: Stopped"; break;
        case Pausing: text = "Scan status changed: Pausing..."; break;
        case Paused: text = "Scan status changed: Paused"; break;
        }
        if (text && scannerLog.isInfoEnabled())
            QMessageLogger(nullptr, 0, nullptr, scannerLog.categoryName()).info().noquote() << text;
    }
    if (next == Finished || next == Stopped || next == Paused)
        m_duration.stop();
    // gui.exe:0x1400E929C..0x1400E92B7 and sms.exe:0x1400E3A6C..0x1400E3A87:
    // provision pending issues, emit finished, then read the current status.
    // The last read occurs after synchronous callbacks, not from cached next.
    if (next == Finished || next == Stopped) {
        m_issueDb.provision(); // gui.exe:0x140127D70 / sms.exe:0x14011A610
        emit finished(); // gui.exe:0x1400EA720
    }
    emit statusChanged(m_status);
}

QJsonArray Scanner::issuesAsJson() const
{
    QJsonArray result;
    for (const Issue &issue : m_issueDb.issues())
        result.append(issue.toJsonObject());
    return result;
}
