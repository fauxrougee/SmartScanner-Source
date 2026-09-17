#include "parameterinjection.h"

#include <QMutexLocker>
#include <QNetworkRequest>
#include <QVariant>

// gui.exe:0x1400F8C80. Embedded parser state at +88 (sub_140133790) is NOT
// reconstructed here; only the recovered base fields and the shared vector
// pointer (+240) are initialized. No fabricated parser state.
ParameterInjection::ParameterInjection(qint32 kind,
                                       const QSharedPointer<InjectionVector> &vector,
                                       const QString &name, const QString &value)
    : Parameter(kind, name, value)
    , m_vector(vector)
{
}

// gui.exe:0x1400880A0. is_valid only delegates to the vector; no base kind test.
bool ParameterInjection::isValid() const
{
    return m_vector && m_vector->isValid();
}

// gui.exe:0x140087390. Locks the recursive mutex; on invalid returns the
// fallback unchanged; mode == 1 returns the stored value when nonempty OR the
// fallback is null, otherwise returns the fallback; in the general case when the
// stored value is nonempty OR the fallback is null, decodes stored UTF-8 through
// the vector's decode chain (decodeTransforms) and converts back to QString,
// otherwise returns the fallback.
QString ParameterInjection::value(const QString &fallback, qint32 mode) const
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (!isValid())
        return fallback; // LABEL_4
    if (mode == 1)
    {
        if (!m_value.isEmpty() || fallback.isNull())
            return m_value;
        return fallback;
    }
    if (!m_value.isEmpty() || fallback.isNull())
    {
        QByteArray bytes = m_vector->decodeTransforms(m_value.toUtf8());
        return QString::fromUtf8(bytes);
    }
    return fallback;
}

// gui.exe:0x140088430. Locks the recursive mutex, no-ops on invalid; mode == 1
// assigns the raw string directly, otherwise applies the vector transform chain
// (applyTransforms) and converts the result back from UTF-8.
void ParameterInjection::setValue(const QString &value, qint32 mode)
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (!isValid())
        return;
    if (mode == 1)
        m_value = value;
    else
        m_value = QString::fromUtf8(m_vector->applyTransforms(value.toUtf8()));
}

// gui.exe:0x140087B10. Three apply overloads under the recursive mutex.
// Invalid -> default QNetworkRequest (not the supplied base). Valid -> the base
// request gets attr 1013 (label), attr 1014 (native metadata with RAW stored
// fields, not decoded getters) and attr 1008 (invalid QVariant); then the
// matching vector apply overload is invoked and its QVariant result is forwarded
// to applyVariant(result, base) and returned, without short-circuiting on an
// invalid vector result.
QNetworkRequest ParameterInjection::apply(qint32 flags, const QByteArray &value,
    const QString &name, const QString &label, QNetworkRequest base)
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (!isValid())
        return QNetworkRequest();
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1013), QVariant(label));
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1014),
                      QVariant::fromValue(BasicParameter{m_name, m_value, m_kind}));
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1008), QVariant());
    const QVariant result = m_vector->apply(flags, value, name);
    return applyVariant(result, base);
}

QNetworkRequest ParameterInjection::apply(qint32 flags, qint32 value,
    const QString &name, const QString &label, QNetworkRequest base)
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (!isValid())
        return QNetworkRequest();
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1013), QVariant(label));
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1014),
                      QVariant::fromValue(BasicParameter{m_name, m_value, m_kind}));
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1008), QVariant());
    const QVariant result = m_vector->apply(flags, value, name);
    return applyVariant(result, base);
}

QNetworkRequest ParameterInjection::apply(qint32 flags, const QString &value,
    const QString &name, const QString &label, QNetworkRequest base)
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (!isValid())
        return QNetworkRequest();
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1013), QVariant(label));
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1014),
                      QVariant::fromValue(BasicParameter{m_name, m_value, m_kind}));
    base.setAttribute(static_cast<QNetworkRequest::Attribute>(1008), QVariant());
    const QVariant result = m_vector->apply(flags, value, name);
    return applyVariant(result, base);
}
