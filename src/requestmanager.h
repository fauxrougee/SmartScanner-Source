#pragma once

#include <QNetworkAccessManager>
#include <QNetworkCookie>
#include <QList>
#include <QPair>
#include <QObject>
#include <QDateTime>
#include <QDir>
#include <QRecursiveMutex>
#include <QSslError>
#include <QTimer>
#include <QHash>
#include <QNetworkRequest>
#include <QSemaphore>
#include <QSharedPointer>
#include <QLoggingCategory>
#include <functional>

class QAuthenticator;
class QNetworkReply;
class QNetworkRequest;

// Partial native SMS RequestManager: constructor, preparation, queue consumers,
// submission, completion and GC. Public enqueue/waiter creation still pending.
class RequestManager final : public QObject {
    Q_OBJECT
public:
    explicit RequestManager(QObject *parent = nullptr);

    [[nodiscard]] int firstLimit() const noexcept { return m_firstLimit; }
    [[nodiscard]] int secondLimit() const noexcept { return m_secondLimit; }
    [[nodiscard]] qint64 timeoutMilliseconds() const noexcept { return m_timeoutMilliseconds; }
    [[nodiscard]] qint64 maximumStoredResponseBytes() const noexcept { return m_maximumStoredResponseBytes; }
    [[nodiscard]] qint64 totalReceivedBytes() const noexcept { return m_totalReceivedBytes; }

    // Reconstructed names for sms.exe:0x140136E50 and 0x140136AB0. These
    // methods are used by the reconstructed native submission path.
    void prepareRequest(QNetworkRequest &request) const;
    void prepareCookies(QNetworkRequest &request, QList<QNetworkCookie> &savedCookies,
                        QList<QNetworkCookie> &injectedCookies);
    // Inverse jar operations observed after sendCustomRequest in 0x140137020.
    void restoreCookies(const QList<QNetworkCookie> &savedCookies,
                        const QList<QNetworkCookie> &injectedCookies);
    // Scope validator for redirect URLs - returns true if URL is allowed
    void setRedirectValidator(std::function<bool(const QUrl &)> validator);

private slots:
    void replyReceived(QNetworkReply *reply);
    void headerReceived();
    void readyReady(); // Exact spelling in sms.exe's Qt metaobject.
    void doNextRequest();
    void stop();
    void pause();
    void resume();
    void authenticate(QNetworkReply *reply, QAuthenticator *authenticator);
    void handleSslErrors(QNetworkReply *reply, const QList<QSslError> &errors);
    void garbageCollect();

signals:
    void finished(QSharedPointer<QNetworkReply> reply);
    void allFinished();

private:
    friend struct RequestManagerNativeTestAccess;
    // Reconstruction labels for 0x140137020, 0x140134C40, 0x140135CA0,
    // and 0x140135880; implementations are in the component source files.
    bool submitPreparedRequest(const QNetworkRequest &request);
    QNetworkRequest takeNextRequest();
    int redirectReply(const QSharedPointer<QNetworkReply> &reply);
    void storeReplyBody(QNetworkReply *reply);

    // Equivalent typed state established by ctor and consumers in SMS.
    qint32 m_state = 0;                                  // +16
    QList<QNetworkRequest> m_requestQueue;               // +40
    QHash<quint64, QSharedPointer<QSemaphore>> m_waiters; // +64
    quint64 m_activeRequestCount = 0;                    // +152
    quint64 m_redirectCount = 0;                         // +136
    QUrl m_lastRequestUrl;                               // +160
    QList<qint64> m_headerDurations;                     // +168
    QList<quint64> m_completedReplyIds;                  // +216
    QHash<quint64, QSharedPointer<QNetworkReply>> m_replies; // +352
    bool m_allFinishedPending = false;                  // +360
    QLoggingCategory m_logCategory{"scanner.requests"}; // +368
    QNetworkAccessManager m_accessManager;
    QTimer m_garbageCollectionTimer;
    // Literal constructor defaults at offsets +72, +76, +80 and +288.
    int m_firstLimit = 6;
    int m_secondLimit = 5;
    qint64 m_timeoutMilliseconds = 90000;
    qint64 m_maximumStoredResponseBytes = 204800;
    // sms.exe:0x140131E7B through 0x140132249. These are retained native
    // construction-state members; their later ownership roles are not named.
    QDir m_cacheDirectory;
    QDateTime m_constructedAt;
    QRecursiveMutex m_mutex;
    // sms.exe:0x14013597D increments the qint64 at native offset +0x128.
    qint64 m_totalReceivedBytes = 0;
    // sms.exe:0x140133703 reads these as the manager-level fallback
    // credentials. Their configuration path remains a separate recovery task.
    QString m_authenticationUser;
    QString m_authenticationPassword;
    // Native +88 QString and +112 QList of 48-byte header pairs. Preserve
    // insertion order and duplicate names; their configuration setters await recovery.
    QString m_userAgent;
    QList<QPair<QByteArray, QByteArray>> m_defaultHeaders;
    std::function<bool(const QUrl &)> m_redirectValidator;
};
