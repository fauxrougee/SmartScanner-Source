#include "keyvalueinjectionvector.h"
#include <QMutexLocker>

KeyValueInjectionVector::KeyValueInjectionVector(const QByteArray &key,
                                               const QByteArray &value)
    : m_key(key), m_value(value) // gui.exe:0x14010FE50
{}

qint32 KeyValueInjectionVector::supportedFlagsRaw() const
{
    return 1; // gui.exe:0x140088500
}

bool KeyValueInjectionVector::isValid() const
{
    return !m_key.isNull(); // gui.exe:0x140088020
}

QVariant KeyValueInjectionVector::apply(qint32 flags, const QByteArray &value,
                                      const QString &name)
{
    // gui.exe:0x140085BA0, wrapped by 0x140086930. Typed empty pair on failure.
    Q_UNUSED(name);
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (!isValid() || !(flags & 1))
        return QVariant::fromValue(NativeBytePair{});
    return QVariant::fromValue(NativeBytePair{m_key, value});
}

QVariant KeyValueInjectionVector::apply(qint32 flags, qint32 value,
                                      const QString &name)
{
    return apply(flags, QString::number(value, 10).toUtf8(), name); // 0x140086840
}

QVariant KeyValueInjectionVector::apply(qint32 flags, const QString &value,
                                      const QString &name)
{
    return apply(flags, value.toUtf8(), name); // gui.exe:0x1400869E0
}
