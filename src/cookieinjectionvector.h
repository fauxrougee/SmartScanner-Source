#pragma once
#include "injectionvector.h"
#include <QRecursiveMutex>
#include <QNetworkCookie>

// Native RTTI spelling, with reconstructed source-level operation names.
class CookieInjectionVector final : public InjectionVector {
public:
    CookieInjectionVector(const QList<QNetworkCookie> &cookies, qint32 selectedIndex);
    qint32 supportedFlagsRaw() const override;
    bool isValid() const override;
    QVariant apply(qint32 flags, const QByteArray &value, const QString &name) override;
    QVariant apply(qint32 flags, qint32 value, const QString &name) override;
    QVariant apply(qint32 flags, const QString &value, const QString &name) override;
private:
    mutable QRecursiveMutex m_mutex;
    QList<QNetworkCookie> m_cookies; // native +64
    qint32 m_selectedIndex; // native +88
};
