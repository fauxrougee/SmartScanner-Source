#include "parameter.h"

#include <QMutexLocker>

// Reconstructed from gui.exe sub_1400F8C80 / sub_14002A690.
Parameter::Parameter(qint32 kind, const QString &name, const QString &value)
    : m_name(name), m_value(value), m_kind(kind) {}

// gui.exe sub_140088040: lock, m_kind != 0, unlock.
bool Parameter::isValid() const {
    QMutexLocker locker(&m_mutex);
    return m_kind != 0;
}

// gui.exe sub_1400891D0 -> sub_14002A690 switch on m_kind.
QString Parameter::kindName() const {
    QMutexLocker locker(&m_mutex);
    switch (m_kind) {
    case 1:
        return QStringLiteral("Query");
    case 2:
        return QStringLiteral("Post");
    case 4:
        return QStringLiteral("Cookie");
    case 8:
        return QStringLiteral("Header");
    case 16:
        return QStringLiteral("Path");
    case 31:
        return QStringLiteral("");  // empty but non-null
    default:
        return QString();  // null
    }
}

// gui.exe sub_140087200: copy m_name under lock.
QString Parameter::name() const {
    QMutexLocker locker(&m_mutex);
    return m_name;
}

// gui.exe sub_140088310: assign m_name under lock.
void Parameter::setName(const QString &name) {
    QMutexLocker locker(&m_mutex);
    m_name = name;
}

// gui.exe sub_1400872E0: stored if !m_value.isEmpty() or fallback.isNull().
QString Parameter::value(const QString &fallback, qint32 mode) const {
    Q_UNUSED(mode);
    QMutexLocker locker(&m_mutex);
    if (!m_value.isEmpty() || fallback.isNull())
        return m_value;
    return fallback;
}

// gui.exe sub_1400883D0: assign m_value under lock.
void Parameter::setValue(const QString &value, qint32 mode) {
    Q_UNUSED(mode);
    QMutexLocker locker(&m_mutex);
    m_value = value;
}

// gui.exe sub_140087280: read m_kind under lock.
qint32 Parameter::kind() const {
    QMutexLocker locker(&m_mutex);
    return m_kind;
}

// gui.exe sub_140088370: write m_kind under lock.
void Parameter::setKind(qint32 kind) {
    QMutexLocker locker(&m_mutex);
    m_kind = kind;
}
