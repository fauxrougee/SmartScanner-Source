#include "mainwebview.h"

#include "webinterface.h"

#include <QCloseEvent>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QScreen>
#include <QSettings>
#include <QStandardPaths>
#include <QJsonArray>
#include <QJsonDocument>
#include <QUrlQuery>
#include <QWebChannel>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <exception>

MainWebView::MainWebView(QWidget *parent) : QWebEngineView(parent) {
    auto *profile = new QWebEngineProfile(QStringLiteral("gui"), this);
    const auto cachePath = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
                           + QStringLiteral("/gui/");
    const auto storagePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                             + QStringLiteral("/gui/");
    profile->setCachePath(cachePath);
    profile->setDownloadPath(cachePath);
    profile->setPersistentStoragePath(storagePath);
    setPage(new QWebEnginePage(profile, this));

    setWindowTitle(QStringLiteral("SmartScanner"));
    setMinimumWidth(850);
    setMinimumHeight(650);
    QSettings settings;
    const auto geometry = settings.value(QStringLiteral("mainwindow/geometry")).toByteArray();
    if (!geometry.isEmpty()) {
        restoreGeometry(geometry);
    } else if (const auto screens = QGuiApplication::screens(); !screens.isEmpty()) {
        const auto bounds = screens.first()->geometry();
        int h = static_cast<int>((bounds.height() - bounds.y() + 1) * 0.8);
        int w = h * 6 / 4;
        int x = bounds.x() + (bounds.width() - bounds.x() - w + 1) / 2;
        int y = bounds.y() + (bounds.height() - bounds.y() - h + 1) / 2;
        setGeometry(x, y, w, h);
    }

    // Hide context menu actions (from decompiled MainWebView_ctor lines 161-204)
    const QList<QWebEnginePage::WebAction> hiddenActions = {
        QWebEnginePage::OpenLinkInThisWindow,
        QWebEnginePage::Back,
        QWebEnginePage::Forward,
        QWebEnginePage::DownloadMediaToDisk,
        QWebEnginePage::DownloadLinkToDisk,
        QWebEnginePage::CopyLinkToClipboard,
        QWebEnginePage::CopyImageUrlToClipboard,
        QWebEnginePage::CopyImageToClipboard,
        QWebEnginePage::DownloadImageToDisk,
        QWebEnginePage::Reload,
        QWebEnginePage::Cut,
        QWebEnginePage::ViewSource,
        QWebEnginePage::InspectElement,
        QWebEnginePage::ExitFullScreen,
        QWebEnginePage::SavePage
    };
    for (auto action : hiddenActions) {
        if (auto *act = page()->action(action))
            act->setVisible(false);
    }

    auto *channel = new QWebChannel(this);
    auto *webInterface = new WebInterface(this);
    channel->registerObject(QStringLiteral("SmartScanner"), webInterface);
    page()->setWebChannel(channel);

    connect(webInterface, &WebInterface::statusChanged, this, [](int status) {
        Q_UNUSED(status)
    });
    connect(webInterface, &WebInterface::issuesUpdated, this, [](const QJsonArray &) {
        // Issues updated
    });
    connect(page(), &QWebEnginePage::pdfPrintingFinished, this, [](const QString &, bool) {
        // Handle PDF printing finished
    });
    connect(this, &QWebEngineView::loadFinished, this, [this](bool) { show(); });

    if (!handleDeepLinks(QCoreApplication::arguments())) setUrl(QUrl(QStringLiteral("qrc:/index.html")));
}

bool MainWebView::handleDeepLinks(const QStringList &arguments) {
    if (arguments.size() <= 1) return false;
    const QUrl url(arguments.at(1));
    if (url.scheme() != QStringLiteral("smartscanner")) return false;
    raise();
    activateWindow();
    // gui.exe:0x14001D103 routes "activate" to LABEL_13, which returns zero.
    if (url.host() != QStringLiteral("scan")) return false;

    // The extracted UI's H8::compile inserts `target` as an object with title
    // and items. gui.exe starts from default-scan-config.json and passes the
    // decoded URL to the Scanner before navigating to this route.
    const auto configPath = QCoreApplication::applicationDirPath()
                            + QStringLiteral("/assets/default-scan-config.json");
    ScanConfig config;
    QString configError;
    // gui.exe:0x14001E6A3..0x14001E6DB loads the default config before
    // decoding the target; its catch path at 0x14001EBA4 returns false.
    try {
        config = ScanConfig::loadFile(configPath, &configError);
    } catch (const std::exception &) {
        return false;
    }
    if (!configError.isEmpty())
        return false;
    // gui.exe:0x14001E700..0x14001E739: query formatting 0, percent decode,
    // then QUrl::fromUserInput with an empty working directory/default flags.
    const QUrl decoded = QUrl::fromUserInput(QUrl::fromPercentEncoding(url.query().toUtf8()));
    auto *bridge = findChild<WebInterface *>();
    if (bridge) {
        config.json().insert(QStringLiteral("target"), QJsonObject{
            {QStringLiteral("title"), QStringLiteral("target")},
            {QStringLiteral("items"), QJsonArray{QJsonObject{
                {QStringLiteral("type"), QStringLiteral("url")},
                {QStringLiteral("data"), decoded.toString()}}}}
        });
        bridge->startScan(config);
    }
    setUrl(QUrl(QStringLiteral("qrc:/index.html/#/scan?loadedProject=true")));
    return true;
}

void MainWebView::closeEvent(QCloseEvent *event) {
    QSettings().setValue(QStringLiteral("mainwindow/geometry"), saveGeometry());
    QWebEngineView::closeEvent(event);
}
