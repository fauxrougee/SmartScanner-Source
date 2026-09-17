#include "cookieinjectionvector.h"
#include <QMutexLocker>

CookieInjectionVector::CookieInjectionVector(const QList<QNetworkCookie> &cookies,
                                           qint32 selectedIndex)
    : m_cookies(cookies), m_selectedIndex(selectedIndex) // gui.exe:0x1400F8AE0
{}

qint32 CookieInjectionVector::supportedFlagsRaw() const
{
    return 17; // gui.exe:0x1400D7260
}

bool CookieInjectionVector::isValid() const
{
    // gui.exe:0x1400AA620: QList length is not narrowed to qint32.
    return !m_cookies.isEmpty() && m_selectedIndex >= 0
        && m_selectedIndex < m_cookies.size();
}

QVariant CookieInjectionVector::apply(qint32 flags, const QByteArray &value,
                                    const QString &name)
{
    // gui.exe:0x1400F8530, wrapped by 0x1400F8FD0: typed empty list on failure.
    Q_UNUSED(name);
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (!isValid() || !(flags & 1))
        return QVariant::fromValue(QList<QNetworkCookie>{});
    QList<QNetworkCookie> result = m_cookies;
    result[m_selectedIndex].setValue((flags & 16) ? value : applyTransforms(value));
    return QVariant::fromValue(result);
}

QVariant CookieInjectionVector::apply(qint32 flags, qint32 value, const QString &name)
{
    return apply(flags, QString::number(value, 10).toUtf8(), name); // 0x1400F8EF0
}

QVariant CookieInjectionVector::apply(qint32 flags, const QString &value,
                                    const QString &name)
{
    return apply(flags, value.toUtf8(), name); // gui.exe:0x1400F9060
}
