#pragma once
#include "injectionvector.h"
#include <QRecursiveMutex>
#include <QJsonObject>

// Native RTTI spelling, with reconstructed source-level operation names.
class JsonObjectyInjectionVector final : public InjectionVector {
public:
    JsonObjectyInjectionVector(const QJsonObject &object, const QString &key);
    qint32 supportedFlagsRaw() const override;
    bool isValid() const override;
    QVariant apply(qint32 flags, const QByteArray &value, const QString &name) override;
    QVariant apply(qint32 flags, qint32 value, const QString &name) override;
    QVariant apply(qint32 flags, const QString &value, const QString &name) override;
private:
    mutable QRecursiveMutex m_mutex;
    QJsonObject m_object; // native +64
    QString m_key; // native +72
};
