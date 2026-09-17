#pragma once
#include "injectionvector.h"
#include <QRecursiveMutex>

// Native RTTI spelling, with reconstructed source-level operation names.
class CustomInjectionVector final : public InjectionVector {
public:
    CustomInjectionVector(const QString &pattern);
    qint32 supportedFlagsRaw() const override;
    bool isValid() const override;
    QVariant apply(qint32 flags, const QByteArray &value, const QString &name) override;
    QVariant apply(qint32 flags, qint32 value, const QString &name) override;
    QVariant apply(qint32 flags, const QString &value, const QString &name) override;
private:
    mutable QRecursiveMutex m_mutex;
    QString m_pattern; // native +64
};
