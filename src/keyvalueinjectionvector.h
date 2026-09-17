#pragma once
#include "injectionvector.h"
#include <QRecursiveMutex>
#include <QPair>

using NativeBytePair = QPair<QByteArray, QByteArray>;
// Native RTTI spelling, with reconstructed source-level operation names.
class KeyValueInjectionVector final : public InjectionVector {
public:
    KeyValueInjectionVector(const QByteArray &key, const QByteArray &value);
    qint32 supportedFlagsRaw() const override;
    bool isValid() const override;
    QVariant apply(qint32 flags, const QByteArray &value, const QString &name) override;
    QVariant apply(qint32 flags, qint32 value, const QString &name) override;
    QVariant apply(qint32 flags, const QString &value, const QString &name) override;
private:
    mutable QRecursiveMutex m_mutex;
    QByteArray m_key; // native +64
    QByteArray m_value; // native +88
};
