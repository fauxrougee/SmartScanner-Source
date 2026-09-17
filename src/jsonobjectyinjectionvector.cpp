#include "jsonobjectyinjectionvector.h"

#include <QJsonDocument>
#include <QJsonValue>
#include <QMutexLocker>
#include <QVariant>

// Native ctor 0x140111E80 stores a copy of the object (native +64) and the key
// (native +72); fields m_object/m_key mirror that layout.
JsonObjectyInjectionVector::JsonObjectyInjectionVector(const QJsonObject &object, const QString &key)
    : m_object(object)
    , m_key(key)
{
}

// 0x140113EA0: writes raw flag mask 27 and returns the out pointer.
qint32 JsonObjectyInjectionVector::supportedFlagsRaw() const
{
    return 27;
}

// 0x140110EB0: non-empty object AND non-empty key AND key present.
bool JsonObjectyInjectionVector::isValid() const
{
    return !m_object.isEmpty() && !m_key.isEmpty() && m_object.contains(m_key);
}

// 0x14010FBD0. Safe because QRecursiveMutex allows re-entrant locking.
QVariant JsonObjectyInjectionVector::apply(qint32 flags, const QString &value, const QString &name)
{
    Q_UNUSED(name)
    QMutexLocker locker(&m_mutex);
    if (!isValid())
        return QVariant();
    QJsonObject copy = m_object; // LOCAL copy, stored object untouched.
    bool edited = false;
    if (flags & 1) {
        if (flags & 0x10) {
            // Raw QString form, no transform, no UTF8 round-trip.
            copy[m_key] = QJsonValue(value);
        } else {
            const QByteArray transformed = applyTransforms(value.toUtf8());
            copy[m_key] = QJsonValue(QString::fromUtf8(transformed));
        }
        edited = true;
    } else if (flags & 2) {
        // QJsonValue::Null, not numeric zero: native ctor takes QJsonValue::Type 0.
        copy[m_key] = QJsonValue(QJsonValue::Null);
        edited = true;
    }
    if (flags & 8) {
        // Independent remove, applied after the value edit and winning over it.
        copy.remove(m_key);
    } else if (!edited) {
        return QVariant();
    }
    return QVariant(QJsonDocument(copy).toJson(QJsonDocument::Indented));
}

// 0x14010FA30: signed int overload, no string conversion or transform at all.
QVariant JsonObjectyInjectionVector::apply(qint32 flags, qint32 value, const QString &name)
{
    Q_UNUSED(name)
    QMutexLocker locker(&m_mutex);
    if (!isValid())
        return QVariant();
    QJsonObject copy = m_object;
    bool edited = false;
    if (flags & 1) {
        copy[m_key] = QJsonValue(value);
        edited = true;
    } else if (flags & 2) {
        copy[m_key] = QJsonValue(QJsonValue::Null);
        edited = true;
    }
    if (flags & 8) {
        copy.remove(m_key);
    } else if (!edited) {
        return QVariant();
    }
    return QVariant(QJsonDocument(copy).toJson(QJsonDocument::Indented));
}

// gui.exe:0x140110340 decodes bytes to QString before the string operation.
QVariant JsonObjectyInjectionVector::apply(qint32 flags, const QByteArray &value, const QString &name)
{
    return apply(flags, QString::fromUtf8(value), name);
}
