#include "mainwebview.h"

#include <QApplication>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QLocalServer>
#include <QLocalSocket>
#include <QLoggingCategory>
#include <QMessageBox>
#include <QSettings>
#include <QSslSocket>
#include <QStandardPaths>
#include <QThread>
#include <QDataStream>
#include <windows.h>

Q_LOGGING_CATEGORY(lcMain, "main")

static const char *kChromiumFlags =
    "--disable-gpu --disable-software-rasterizer --disable-gpu-compositing "
    "--disable-web-security --allow-insecure-localhost --ignore-certificate-errors "
    "--hide-scrollbars --disable-features=UserAgentClientHint --disable-background-networking "
    "--mainFrameClipsContent=false --disable-extensions --disable-background-timer-throttling "
    "--disable-backgrounding-occluded-windows --disable-client-side-phishing-detection "
    "--disable-component-extensions-with-background-pages --disable-features=TranslateUI "
    "--disable-hang-monitor --disable-popup-blocking --disable-ipc-flooding-protection "
    "--disable-prompt-on-repost --disable-renderer-backgrounding --disable-sync "
    "--force-color-profile=srgb --metrics-recording-only --enable-blink-features=IdleDetection "
    "--disable-ipc-flooding-protection --blink-settings=dnsPrefetchingEnabled=false "
    "--dns-prefetch-disable --font-render-hinting=none --disable-auto-reload --disable-breakpad "
    "--disable-component-cloud-policy --disable-crash-reporter --disable-default-apps "
    "--disable-dinosaur-easter-egg --disable-domain-reliability --window-size=1950,1200 "
    "--process-per-site --no-sandbox --safebrowsing-disable-auto-update --disable-setuid-sandbox "
    "--disable-sync --metrics-recording-only --disable-translate --no-zygote --mute-audio "
    "--disable-canvas-aa --disable-2d-canvas-clip-aa --disable-dev-shm-usage --disable-infobars "
    "--no-first-run";

static void logStartupInfo() {
    qCInfo(lcMain) << "SmartScanner" << "3.0.0" << "x64" << "3.0-0-g78416121" << "Pro";
    qCInfo(lcMain) << "QSslSocket::supportsSsl()=" << QSslSocket::supportsSsl()
                   << "QSslSocket::sslLibraryBuildVersionNumber()=" << QSslSocket::sslLibraryBuildVersionNumber()
                   << "QSslSocket::sslLibraryBuildVersionString()=" << QSslSocket::sslLibraryBuildVersionString()
                   << "QSslSocket::sslLibraryVersionNumber()=" << QSslSocket::sslLibraryVersionNumber()
                   << "QSslSocket::sslLibraryVersionString()=" << QSslSocket::sslLibraryVersionString();
    qCInfo(lcMain) << "QThread::idealThreadCount()=" << QThread::idealThreadCount();
}

static void cleanCache() {
    const QString cachePath = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
    bool cacheRemoved = QDir(cachePath).removeRecursively();

    const QString webEnginePath = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
                                  + QStringLiteral("/QtWebEngine/");
    bool webEngineRemoved = QDir(webEnginePath).removeRecursively();

    qCInfo(lcMain) << "Cleaning cache:" << cacheRemoved << webEngineRemoved;
}

static void incrementRunCount() {
    QSettings settings;
    int runCount = settings.value(QStringLiteral("run"), 0).toInt();
    settings.setValue(QStringLiteral("run"), runCount + 1);
}

static void setupChromiumFlags() {
    if (!qEnvironmentVariableIsSet("QTWEBENGINE_CHROMIUM_FLAGS")) {
        qCInfo(lcMain) << "set env";
        qputenv("QTWEBENGINE_CHROMIUM_FLAGS", kChromiumFlags);
    } else {
        qCInfo(lcMain) << "QTWEBENGINE_CHROMIUM_FLAGS=" << qEnvironmentVariableIsSet("QTWEBENGINE_CHROMIUM_FLAGS");
    }
}

static bool sendArgsToRunningInstance(QLocalSocket *socket, const QStringList &args) {
    if (!socket || !socket->isOpen())
        return false;

    QDataStream stream(socket);
    stream << args;
    socket->flush();
    socket->waitForBytesWritten(200);
    return true;
}

static void showInstanceLimitMessage() {
    QMessageBox::information(
        nullptr,
        QStringLiteral("SmartScanner Instance Limit"),
        QStringLiteral("SmartScanner is already running.\n\n"
                       "The Free version allows only one instance at a time. "
                       "Upgrade to SmartScanner Pro with an active license to run multiple instances. "
                       "Visit our website to learn more and upgrade."),
        QMessageBox::Ok);
}

int main(int argc, char *argv[]) {
    HANDLE mutex = CreateMutexW(nullptr, FALSE, L"SmartScannerInnoSetupMutex");
    DWORD lastError = GetLastError();

    QCoreApplication::setOrganizationName(QStringLiteral("TheSmartScanner"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("thesmartscanner.com"));
    QCoreApplication::setApplicationName(QStringLiteral("SmartScanner"));
    QCoreApplication::setApplicationVersion(QStringLiteral("3.0.0"));

    QApplication app(argc, argv);

    bool isFirstInstance = (mutex && lastError != ERROR_ALREADY_EXISTS);

    QLocalSocket *existingSocket = nullptr;
    QLocalServer *server = nullptr;

    if (!isFirstInstance) {
        existingSocket = new QLocalSocket();
        existingSocket->connectToServer(QStringLiteral("SmartScanner"));
        existingSocket->waitForConnected(1000);
    }

    if (isFirstInstance) {
        logStartupInfo();

        cleanCache();
        incrementRunCount();
        setupChromiumFlags();

        Q_INIT_RESOURCE(gui_resources);

        auto *window = new MainWebView();

        server = new QLocalServer(&app);
        server->listen(QStringLiteral("SmartScanner"));
        QObject::connect(server, &QLocalServer::newConnection, [window, server]() {
            QLocalSocket *client = server->nextPendingConnection();
            if (client) {
                QObject::connect(client, &QLocalSocket::readyRead, [window, client]() {
                    QDataStream stream(client);
                    QStringList args;
                    stream >> args;
                    window->handleDeepLinks(args);
                    client->deleteLater();
                });
            }
        });

        int result = app.exec();

        cleanCache();

        qCInfo(lcMain) << "exit:" << result;

        delete window;
        return result;
    } else {
        QStringList args = QCoreApplication::arguments();
        if (args.size() > 1) {
            sendArgsToRunningInstance(existingSocket, args);
            return 0;
        } else {
            showInstanceLimitMessage();
            sendArgsToRunningInstance(existingSocket, {QStringLiteral("smartscanner://activate")});
        }
    }

    if (existingSocket) {
        existingSocket->disconnectFromServer();
        delete existingSocket;
    }

    return 0;
}
