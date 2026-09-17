#pragma once

#include <QNetworkCookie>
#include <QNetworkCookieJar>
#include <QRecursiveMutex>

// sms.exe ThreadSafeCookieJar_ctor at 0x14015FBC0 establishes this exact base
// class plus a QRecursiveMutex. The overrides below are the native vtable
// entries at 0x14015FC50, 0x14015FD70, 0x14015FDE0, 0x14015FE50, and
// 0x14015FEC0.
class ThreadSafeCookieJar final : public QNetworkCookieJar {
public:
    explicit ThreadSafeCookieJar(QObject *parent = nullptr);

    [[nodiscard]] QList<QNetworkCookie> cookiesForUrl(const QUrl &url) const override;
    bool deleteCookie(const QNetworkCookie &cookie) override;
    bool insertCookie(const QNetworkCookie &cookie) override;
    bool setCookiesFromUrl(const QList<QNetworkCookie> &cookies, const QUrl &url) override;
    bool updateCookie(const QNetworkCookie &cookie) override;

private:
    mutable QRecursiveMutex m_mutex;
};
