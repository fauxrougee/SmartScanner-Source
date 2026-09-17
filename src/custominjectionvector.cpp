#include "custominjectionvector.h"

#include <QMutexLocker>

namespace {
constexpr qint32 kFlagMandatory = 0x1;   // ligne 140: (v10 & 1)
constexpr qint32 kFlagRawInject = 0x10;  // ligne 142: (v10 & 0x10)
constexpr char kPlaceholder[] = "_Inject_Here_";
}

// 0x140112530 : vtable CustomInjectionVector, pattern copie dans m_pattern.
CustomInjectionVector::CustomInjectionVector(const QString &pattern)
    : m_pattern(pattern)
{
}

// 0x1400D7260 : *a2 = 17
qint32 CustomInjectionVector::supportedFlagsRaw() const
{
    return 17;
}

// 0x1400D7240 : !QString::isNull(+64)
bool CustomInjectionVector::isValid() const
{
    return !m_pattern.isNull();
}

// 0x1400D7690 via 0x1400D7270 : QString -> toUtf8 -> core
QVariant CustomInjectionVector::apply(qint32 flags, const QString &value, const QString &name)
{
    Q_UNUSED(name);
    return apply(flags, value.toUtf8(), name);
}

// 0x1400D7690 via 0x1400D7330 : QString::number((int)value, 10) -> toUtf8 -> core
QVariant CustomInjectionVector::apply(qint32 flags, qint32 value, const QString &name)
{
    Q_UNUSED(name);
    return apply(flags, QString::number(value, 10).toUtf8(), name);
}

// 0x1400D7690 : coeur verrouille, masque 1 et 0x10.
QVariant CustomInjectionVector::apply(qint32 flags, const QByteArray &value, const QString &name)
{
    Q_UNUSED(name);
    QMutexLocker locker(&m_mutex);

    if (!isValid()) {
        return QVariant(QString()); // QString null en cas d'invalidite
    }

    if ((flags & kFlagMandatory) == 0) {
        return QVariant(QString()); // QString null, bits insuffisants
    }

    QString result = m_pattern; // copie, pattern d'origine non modifie
    if ((flags & kFlagRawInject) != 0) {
        // Remplacement direct, sans chaine de transforms.
        result.replace(QString::fromUtf8(kPlaceholder), QString::fromUtf8(value), Qt::CaseSensitive);
    } else {
        QByteArray encoded = applyTransforms(QByteArray(value)).toPercentEncoding();
        result.replace(QString::fromUtf8(kPlaceholder), QString::fromUtf8(encoded), Qt::CaseSensitive);
    }
    return QVariant(result);
}
