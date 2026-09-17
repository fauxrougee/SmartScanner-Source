#include "networkmanager.h"

#include <QCoreApplication>
#include <QFutureWatcher>
#include <QNetworkRequest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost))
        return 1;
    QObject::connect(&server, &QTcpServer::newConnection, &server, [&server] {
        QTcpSocket *socket = server.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket] {
            socket->readAll(); // Keep the request active until NetworkManager aborts it.
        });
    });

    NetworkManager manager{QString()};
    manager.setConcurrentLimit(1);
    const QUrl url(QStringLiteral("http://127.0.0.1:%1/hold").arg(server.serverPort()));
    const auto active = manager.submit(QNetworkRequest(url), QByteArrayLiteral("GET"),
                                       {}, 0, QVariant(), 0, 0);
    const auto pending = manager.submit(QNetworkRequest(url), QByteArrayLiteral("GET"),
                                        {}, 0, QVariant(), 0, 0);

    QFutureWatcher<NetworkManager::ResponsePointer> activeWatcher;
    QFutureWatcher<NetworkManager::ResponsePointer> pendingWatcher;
    int finishedCount = 0;
    QObject::connect(&activeWatcher, &QFutureWatcherBase::finished, &application,
                     [&] { if (++finishedCount == 2) application.quit(); });
    QObject::connect(&pendingWatcher, &QFutureWatcherBase::finished, &application,
                     [&] { if (++finishedCount == 2) application.quit(); });
    activeWatcher.setFuture(active);
    pendingWatcher.setFuture(pending);
    manager.stop();
    QTimer::singleShot(5000, &application, &QCoreApplication::quit);
    application.exec();

    return activeWatcher.isFinished() && pendingWatcher.isFinished()
               && pendingWatcher.future().isCanceled() && manager.isIdle()
           ? 0
           : 2;
}
