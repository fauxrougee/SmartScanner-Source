#pragma once

#include <QDateTime>
#include <QDataStream>
#include <QFuture>
#include <QHash>
#include <QList>
#include <QObject>
#include <QPromise>
#include <QQueue>
#include <QPair>
#include <QRecursiveMutex>
#include <QSet>
#include <QSharedPointer>
#include <QString>
#include <QUrl>
#include <QVariant>
#include <functional>

#include "httpclient.h"

class QAuthenticator;
class QNetworkAccessManager;
class QNetworkCookie;
class QNetworkDiskCache;
class QNetworkProxy;
class QNetworkReply;

// Clean-room reconstruction of the constructor-visible portion of
// sms.exe NetworkManager (0x140123F00).
class NetworkManager final : public QObject {
    Q_OBJECT
public:
    using ResponsePointer = QSharedPointer<const HttpResponse>;

    explicit NetworkManager(const QString &scanId, QObject *parent = nullptr);

    // Native component slice within gui.exe:0x1400E2910 / 0x1400E1CA0.
    friend QDataStream &operator<<(QDataStream &stream, const NetworkManager &manager);
    friend QDataStream &operator>>(QDataStream &stream, NetworkManager &manager);

    // gui.exe:0x140130970 / 0x140130DA0 / 0x140131020 / 0x14012E020.
    [[nodiscard]] bool isIdle() const;
    [[nodiscard]] qint32 concurrentLimit() const noexcept { return m_concurrentLimit; }
    [[nodiscard]] quint32 activeRequests() const;
    [[nodiscard]] quint32 queuedRequests() const;
    [[nodiscard]] quint32 totalRequests() const;
    [[nodiscard]] quint32 completedRequests() const;
    [[nodiscard]] QUrl lastUrl() const;
    [[nodiscard]] QString cacheDirectory() const { return m_cacheDirectory; }

    // gui.exe:0x140132B00 clamps this setting to one and immediately pumps
    // queued work. gui.exe:0x140132AC0 replaces both fallback credentials.
    void setConcurrentLimit(qint32 limit);
    void setAuthenticationCredentials(const QString &user, const QString &password);
    void setTransferTimeout(qint64 timeout);
    void setUserAgent(const QString &userAgent);
    void setDefaultHeaders(const QList<QPair<QByteArray, QByteArray>> &headers);
    void setProxy(const QNetworkProxy &proxy);
    void setCookies(const QList<QNetworkCookie> &cookies);
    // Scope validator for redirect URLs - returns true if URL is allowed
    void setScopeValidator(std::function<bool(const QUrl &)> validator);
    // gui.exe:0x14012DF20. Exact key only; unlike dispatch, no fallback0.
    QList<QNetworkCookie> cookiesForUrl(const QUrl &url, qint32 key = 0) const;

    // gui.exe:0x14012D300. This is invoked by Scanner_stop before the queued
    // Scanner::checkFinished call. It is terminal for this manager instance.
    void stop();

    // Reconstruction label for gui.exe:0x140132220.  The parameter order is
    // recovered from the call site and the function's QNetworkRequest writes:
    // request, method, payload, attributes 1011/1012, access-manager key,
    // then the native queue selector (1: prepend, otherwise append).
    // Missing keys select entry zero; producers for other entries are pending.
    [[nodiscard]] QFuture<ResponsePointer> submit(
        const QNetworkRequest &request, const QByteArray &method,
        const QByteArray &payload, qint32 field1011, const QVariant &field1012,
        qint32 accessManagerKey, qint32 queueSelector);

private slots:
    void authenticate(QNetworkReply *reply, QAuthenticator *authenticator);

signals:
    // gui.exe:0x1401647A0 and 0x140164780, respectively.
    void finished(NetworkManager::ResponsePointer response);
    void allFinished();

private:
    struct PendingRequest {
        QNetworkRequest request;
        QByteArray method;
        QByteArray payload;
        qint32 field1011 = 0;
        QVariant field1012;
        qint32 accessManagerKey = 0;
        qint32 queueSelector = 0;
        QSharedPointer<QPromise<ResponsePointer>> promise;
    };

    void pump();
    void dispatch(PendingRequest work);
    [[nodiscard]] QNetworkAccessManager *selectedManager(qint32 key) const;
    void prepareCookies(QNetworkRequest &request, QNetworkAccessManager *manager,
        QList<QNetworkCookie> &saved, QList<QNetworkCookie> &injected);
    void finish(PendingRequest work, QNetworkReply *reply);
    [[nodiscard]] static ResponsePointer responseFromReply(
        QNetworkReply *reply, const QNetworkRequest &request);

    QNetworkAccessManager *m_accessManager = nullptr;
    // gui.exe:0x140130F90, native +272. Constructor establishes key zero.
    QHash<qint32, QNetworkAccessManager *> m_managersByKey;
    QNetworkDiskCache *m_diskCache = nullptr;
    // The GUI layout begins with this mutex at +0x10. All metric readers use
    // it in the native code.
    mutable QRecursiveMutex m_mutex;
    QString m_cacheDirectory;
    // gui.exe NetworkManager_ctor 0x14012B2B0 initializes these at +0x40,
    // +0x44, +0x48 and +0x4c respectively.
    qint32 m_state = 0;
    qint32 m_concurrentLimit = 5;
    quint32 m_activeRequests = 0;
    quint32 m_totalRequests = 0;
    QUrl m_lastUrl;
    QDateTime m_constructedAt;
    // Native +0x70: one QList<qint64>, not three independent scalar fields.
    // Its entries are written by gui.exe:0x1400D9DC0. Producer still pending.
    QList<qint64> m_field70;
    // gui.exe:0x140131080 reads pending work at NetworkManager+0xc8.
    quint32 m_queuedRequests = 0;
    QQueue<PendingRequest> m_pendingRequests;
    // Source-side ownership form of the native active-reply table at +0x108.
    // It lets the directly observed stop route abort every live reply.
    QSet<QNetworkReply *> m_activeReplies;
    // sms.exe:0x140126A83 uses these manager-level fallback credentials.
    QString m_authenticationUser;
    QString m_authenticationPassword;
    // gui.exe NetworkManager_ctor 0x14012B336 initializes this member at
    // +0x60 to zero.  No recovered public setter writes it, so its default
    // keeps the body-limit path disabled unless a future recovery identifies
    // the owning configuration field.
    qint64 m_maximumResponseBodyBytes = 0;
    qint64 m_transferTimeout = 0;
    QString m_userAgent;
    QList<QPair<QByteArray, QByteArray>> m_defaultHeaders;
    std::function<bool(const QUrl &)> m_scopeValidator;
};
