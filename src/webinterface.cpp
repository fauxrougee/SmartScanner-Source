#include "webinterface.h"
#include "reportgenerator.h"

#include <QCoreApplication>
#include <QFile>
#include <QFileDialog>
#include <QJsonDocument>
#include <QDateTime>
#include <QMessageBox>
#include <QUrl>
#include <QUuid>
#include <QTextStream>
#include <QStringConverter>

#include <algorithm>
#include <cmath>

namespace {

QVariant scannerValue(const QVariantMap &values, const char *name)
{
    // WebInterface_getUpdate (gui.exe:0x140024C30) looks up every key in the
    // Scanner-provided QMap and uses QVariant(0) when absent.
    return values.value(QString::fromLatin1(name), QVariant(0));
}

QString reconstructedTargetText(const ScanConfig &config)
{
    // The native target formatter is ScanConfig+0x180 -> 0x140120BB0.  The
    // current ScanConfig representation retains the single-target JSON shape
    // already used by this reconstruction; the native multi-target item
    // renderer remains separately untranscribed.
    const auto targetItems = config.json().value(QStringLiteral("target")).toObject()
                                 .value(QStringLiteral("items")).toArray();
    if (targetItems.isEmpty())
        return {};
    const auto data = targetItems.first().toObject().value(QStringLiteral("data"));
    return data.isArray() && !data.toArray().isEmpty()
        ? data.toArray().at(0).toString()
        : data.toString();
}

QString scannerStatusText(Scanner::ScanStatus status)
{
    // gui.exe:0x1400EA2C0
    switch (status) {
    case Scanner::Idle: return QStringLiteral("idle");
    case Scanner::Scanning: return QStringLiteral("inprogress");
    case Scanner::Finished: return QStringLiteral("finished");
    case Scanner::Stopping: return QStringLiteral("stopping");
    case Scanner::Stopped: return QStringLiteral("stopped");
    case Scanner::Pausing: return QStringLiteral("pausing");
    case Scanner::Paused: return QStringLiteral("paused");
    }
    return QStringLiteral("unknown");
}

bool updatesProgress(Scanner::ScanStatus status)
{
    // gui.exe:0x1400E72A0: statuses 1, 3 and 5 only.
    return status == Scanner::Scanning || status == Scanner::Stopping
        || status == Scanner::Pausing;
}

} // namespace

WebInterface::WebInterface(QObject *parent) : QObject(parent) {}

QJsonArray WebInterface::issues() const noexcept {
    return m_scanner ? m_scanner->issuesAsJson() : QJsonArray();
}

QJsonObject WebInterface::version() const {
    return {{QStringLiteral("version"), QStringLiteral("3.0.0")},
            {QStringLiteral("build"), QStringLiteral("3.0-0-g78416121")},
            {QStringLiteral("edition"), QStringLiteral("Pro")},
            {QStringLiteral("os"), QStringLiteral("x64")}};
}

QJsonObject WebInterface::userInfoAtStartup() const {
    return {{QStringLiteral("userId"), QStringLiteral("reconstructed-user")},
            {QStringLiteral("license"), QJsonObject{{QStringLiteral("status"), 10}}}};
}

Scanner *WebInterface::ensureScanner() {
    if (m_scanner) return m_scanner;
    m_scanner = new Scanner(this);
    connect(m_scanner, &Scanner::statusChanged, this, [this](Scanner::ScanStatus status) {
        emit statusChanged(static_cast<int>(status));
    });
    connect(m_scanner, &Scanner::issuesUpdated, this, &WebInterface::issuesUpdated);
    connect(m_scanner, &Scanner::log, this, &WebInterface::log);
    return m_scanner;
}

void WebInterface::newScan() {
    if (m_scanner) {
        m_scanner->stop();
        // gui.exe:0x1400268D0 invokes Scanner's deleting destructor before
        // clearing WebInterface+0x10; it does not defer deletion.
        delete m_scanner;
        m_scanner = nullptr;
    }
}

void WebInterface::startScan(const QJsonObject &configJson) {
    startScan(ScanConfig::fromJson(configJson));
}

void WebInterface::startScan(const ScanConfig &config)
{
    // gui.exe:0x1400281F0 has one guarded creation path. A call while a
    // scanner exists is deliberately ignored.
    if (m_scanner)
        return;

    qDebug() << "WebInterface::startScan - Starting scan";
    qDebug() << "  Config JSON keys:" << config.json().keys();
    qDebug() << "  Target items count:" << config.initialRequestItems().size();
    for (const auto &item : config.initialRequestItems()) {
        qDebug() << "    URL:" << item->url();
    }

    // The native writes both fields before constructing Scanner.
    m_progress = 0.0;
    m_progressTicks = 0;
    Scanner *scanner = ensureScanner();
    scanner->applyConfig(config);
    m_target = reconstructedTargetText(config);
    qDebug() << "  Target:" << m_target;
    scanner->start();
    qDebug() << "  Scanner started, status:" << static_cast<int>(scanner->status());
}

void WebInterface::pauseScan() { if (m_scanner) m_scanner->pause(); }
void WebInterface::resumeScan() { if (m_scanner) m_scanner->resume(); }
void WebInterface::stopScan() { if (m_scanner) m_scanner->stop(); }

void WebInterface::saveReport(const QString &reportTemplate, const QString &reportFormat,
                              const QJsonObject &data) {
    Q_UNUSED(data)
    emit log(0, QStringLiteral("report"),
             QStringLiteral("Report export requested (%1)").arg(reportFormat));

    if (!m_scanner) {
        emit printDone(false, QString());
        return;
    }

    // Build ScanReport from current scanner state
    ScanReport report;
    report.targetUrl = m_target;
    report.scanId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    report.startTime = QDateTime::currentDateTime().addSecs(-m_scanner->duration().elapsedSeconds());
    report.endTime = QDateTime::currentDateTime();

    const QVariantMap values = m_scanner->updateValues();
    report.totalRequests = values.value(QStringLiteral("request_total")).toInt();

    // Get issues from scanner's IssueDb
    const QJsonArray issueArray = issues();
    report.totalVulnerabilities = issueArray.size();

    for (const QJsonValue &val : issueArray) {
        QJsonObject obj = val.toObject();
        VulnerabilityReport vuln;
        vuln.id = obj.value(QStringLiteral("id")).toString();
        vuln.title = obj.value(QStringLiteral("name")).toString();
        vuln.severity = obj.value(QStringLiteral("severity")).toString();
        vuln.url = obj.value(QStringLiteral("url")).toString();
        vuln.description = obj.value(QStringLiteral("description")).toString();
        vuln.remediation = obj.value(QStringLiteral("remediation")).toString();
        vuln.discoveredAt = QDateTime::currentDateTime();

        report.vulnerabilities.append(vuln);
        report.severityCounts[vuln.severity]++;
    }

    // Generate report content based on format
    QString content;
    QString defaultExt;
    QString filters;

    if (reportFormat == QStringLiteral("json")) {
        content = ReportGenerator::generateJsonReport(report);
        defaultExt = QStringLiteral(".json");
        filters = QStringLiteral("JSON Files (*.json)");
    } else if (reportFormat == QStringLiteral("html")) {
        content = ReportGenerator::generateHtmlReport(report);
        defaultExt = QStringLiteral(".html");
        filters = QStringLiteral("HTML Files (*.html)");
    } else if (reportFormat == QStringLiteral("pdf")) {
        content = ReportGenerator::generateHtmlReport(report);
        defaultExt = QStringLiteral(".html");
        filters = QStringLiteral("HTML Files (*.html);;PDF Files (*.pdf)");
    } else if (reportFormat == QStringLiteral("xml")) {
        content = ReportGenerator::generateXmlReport(report);
        defaultExt = QStringLiteral(".xml");
        filters = QStringLiteral("XML Files (*.xml)");
    } else if (reportFormat == QStringLiteral("csv")) {
        content = ReportGenerator::generateCsvReport(report);
        defaultExt = QStringLiteral(".csv");
        filters = QStringLiteral("CSV Files (*.csv)");
    } else if (reportFormat == QStringLiteral("markdown") || reportFormat == QStringLiteral("md")) {
        content = ReportGenerator::generateMarkdownReport(report);
        defaultExt = QStringLiteral(".md");
        filters = QStringLiteral("Markdown Files (*.md)");
    } else {
        content = ReportGenerator::generateTextReport(report);
        defaultExt = QStringLiteral(".txt");
        filters = QStringLiteral("Text Files (*.txt)");
    }

    // Show save dialog
    QString filePath = showSaveDialog(QStringLiteral("Save Report"), filters);
    if (filePath.isEmpty()) {
        emit printDone(false, QString());
        return;
    }

    // Ensure proper extension
    if (!filePath.contains(QLatin1Char('.'))) {
        filePath += defaultExt;
    }

    // Save the file
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        out << content;
        file.close();
        emit log(0, QStringLiteral("report"), QStringLiteral("Report saved to: ") + filePath);
        emit printDone(true, filePath);
    } else {
        emit log(1, QStringLiteral("report"), QStringLiteral("Failed to save report: ") + file.errorString());
        emit printDone(false, QString());
    }
}

void WebInterface::catchCookie(const QString &cookie) {
    emit log(0, QStringLiteral("cookie"), cookie);
}

void WebInterface::registerLicense(const QString &license) {
    Q_UNUSED(license)
    // The extracted web UI invokes this method and listens to
    // registrationResults(status, message, details). Its licensing protocol
    // has not been transcribed from the binary yet.
    emit registrationResults(0, QStringLiteral("License registration is not reconstructed"), {});
}

QString WebInterface::removeLicense() {
    // QWebChannel returns this value to the UI callback; empty denotes success
    // in the extracted UI's onRemoveLicense branch.
    return {};
}

void WebInterface::setUiUpdateEnabled(bool enabled) { m_uiUpdatesEnabled = enabled; }
void WebInterface::alert(const QString &message) { emit log(1, QStringLiteral("alert"), message); }
void WebInterface::handleLog(int type, const QString &category, const QString &message) {
    if (m_uiUpdatesEnabled) emit log(type, category, message);
}
QJsonObject WebInterface::getUpdate() {
    // The native early return is an empty object, rather than a fabricated
    // idle-state payload, when Scanner has not been created.
    if (!m_scanner)
        return {};

    const QVariantMap values = m_scanner->updateValues();
    const QVariant last = scannerValue(values, "request_last");
    const qint64 crawled = scannerValue(values, "crawler_crawled").toInt();
    const qint64 queued = scannerValue(values, "crawler_queued").toInt();
    const qint64 totalRequests = scannerValue(values, "request_total").toInt();
    const qint64 completed = scannerValue(values, "request_completed").toInt();
    const qint64 tests = scannerValue(values, "event_progressValue").toInt();
    const qint64 totalTests = scannerValue(values, "event_progressMax").toInt();

    double calculatedProgress = 0.05;
    if (!((queued <= 20 || completed <= 5 || tests <= 5)
          && m_scanner->duration().elapsedSeconds() <= 45)) {
        calculatedProgress = (crawled + completed + tests)
            / static_cast<double>(queued + queued * totalTests / crawled
                                  + queued * totalRequests / crawled);
    }

    const auto state = m_scanner->status();
    double displayedProgress = 0.0;
    if (!updatesProgress(state)) {
        displayedProgress = std::max(m_progress, 0.005);
    } else if (calculatedProgress >= 1.0) {
        m_progress = 1.0;
        displayedProgress = 1.0;
    } else {
        const double oldProgress = m_progress;
        double targetProgress = calculatedProgress;
        double factor = 0.0;
        if (oldProgress > calculatedProgress || calculatedProgress < 0.1) {
            targetProgress = std::min(0.98, (1.0 - calculatedProgress) * 0.08
                                      + calculatedProgress);
            factor = 0.005;
        } else {
            const double scale = calculatedProgress
                / std::max(0.000001, static_cast<double>(m_progressTicks) / 500.0);
            factor = std::pow(calculatedProgress, 1.5)
                * (1.0 - std::exp(static_cast<double>(m_progressTicks) * -0.03))
                * std::clamp(scale, 0.0, 1.0);
        }
        ++m_progressTicks;
        const double candidate = (targetProgress - oldProgress) * factor + oldProgress;
        m_progress = std::max(oldProgress, std::min(1.0, candidate));
        displayedProgress = std::max(m_progress, 0.005);
    }

    const QString lastUrl = last.toUrl()
        .toString(QUrl::FormattingOptions(65)).mid(2);
    return {
        {QStringLiteral("target"), m_target},
        {QStringLiteral("lastUrl"), lastUrl},
        {QStringLiteral("progress"), displayedProgress * 100.0},
        {QStringLiteral("duration"), m_scanner->duration().toDisplayString()},
        {QStringLiteral("date"), m_scanner->startedDate().toString(Qt::TextDate)},
        {QStringLiteral("requests"), completed},
        {QStringLiteral("totalRequests"), totalRequests},
        {QStringLiteral("discoveredUrls"), scannerValue(values, "crawler_discovered").toLongLong()},
        {QStringLiteral("queuedUrls"), scannerValue(values, "crawler_queued").toLongLong()},
        {QStringLiteral("crawledUrls"), scannerValue(values, "crawler_crawled").toLongLong()},
        {QStringLiteral("skippedUrls"), QJsonObject::fromVariantMap(
            scannerValue(values, "crawler_skipped").toMap())},
        {QStringLiteral("tests"), scannerValue(values, "event_progressValue").toLongLong()},
        {QStringLiteral("totalTests"), scannerValue(values, "event_progressMax").toLongLong()},
        {QStringLiteral("status"), scannerStatusText(state)}
    };
}
QJsonObject WebInterface::getUserInfo() const { return userInfoAtStartup(); }

QString WebInterface::showOpenDialog(const QString &title, const QString &filters) {
    return QFileDialog::getOpenFileName(nullptr, title, {}, filters);
}

QString WebInterface::showSaveDialog(const QString &title, const QString &filters) {
    return QFileDialog::getSaveFileName(nullptr, title, {}, filters);
}

int WebInterface::showInfoMessage(const QString &title, const QString &text) {
    return QMessageBox::information(nullptr, title, text);
}

int WebInterface::showWarningMessage(const QString &title, const QString &text) {
    return QMessageBox::warning(nullptr, title, text);
}

QString WebInterface::assetPath(const QString &fileName) const {
    return QCoreApplication::applicationDirPath() + QStringLiteral("/assets/") + fileName;
}

QJsonObject WebInterface::defaultScanConfig() const {
    const QString path = assetPath(QStringLiteral("default-scan-config.json"));
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        qCritical() << "defaultScanConfig: Cannot open file:" << path;
        // Return minimal valid config
        return QJsonDocument::fromJson(R"({"version":"3.0","tests":{"scripts":[]}})").object();
    }

    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        qCritical() << "defaultScanConfig: JSON parse error:" << parseError.errorString();
        return QJsonDocument::fromJson(R"({"version":"3.0","tests":{"scripts":[]}})").object();
    }

    qDebug() << "defaultScanConfig: Loaded successfully, keys:" << doc.object().keys();
    return doc.object();
}

bool WebInterface::saveScan(const QString &path) const {
    if (!m_scanner) return false;
    QFile output(path);
    if (!output.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    // gui.exe calls a native Scanner QDataStream operator at 0x1400E2910.
    // This JSON project format is a temporary reconstruction format, not `.smsp`
    // wire-compatible output, until that operator is transcribed.
    return output.write(QJsonDocument(m_scanner->config().json()).toJson()) >= 0;
}

bool WebInterface::loadScan(const QString &path) {
    QString error;
    const auto config = ScanConfig::loadFile(path, &error);
    if (!error.isEmpty()) {
        emit log(3, QStringLiteral("config"), error);
        emit loadFinished(false);
        return false;
    }
    // The original path reads Scanner's QDataStream state. This temporary JSON
    // format contains only ScanConfig, so apply only the recovered config-copy
    // portion instead of inventing a Scanner restoration lifecycle.
    ensureScanner()->applyConfig(config);
    emit loadFinished(true);
    return true;
}
