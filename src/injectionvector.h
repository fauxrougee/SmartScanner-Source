#pragma once
#include <QByteArray>
#include <QList>
#include <QMutex>
#include <QSharedPointer>
#include <QString>
#include <QVariant>

// Reconstruction label for the byte-transform virtual invoked by 0x140086EF0.
class NativeByteTransform {
public:
    virtual QByteArray transform(const QByteArray &input) = 0;
    // Second observed virtual, 0x140086D50. No default inverse is fabricated.
    virtual QByteArray decode(const QByteArray &input) = 0;
    virtual ~NativeByteTransform() = default;
};

// RTTI name retained. Five native operations, using source-level arguments
// instead of the ABI's packed argument records. Not a binary-layout clone.
class InjectionVector {
public:
    virtual qint32 supportedFlagsRaw() const = 0;
    virtual QVariant apply(qint32 flags, const QByteArray &value, const QString &name) = 0;
    virtual QVariant apply(qint32 flags, qint32 value, const QString &name) = 0;
    virtual QVariant apply(qint32 flags, const QString &value, const QString &name) = 0;
    virtual bool isValid() const = 0;
    virtual ~InjectionVector() = default;
    QList<QSharedPointer<NativeByteTransform>> field10;
protected:
    friend class ParameterInjection;
    friend class Manipulator;
    QByteArray applyTransforms(QByteArray input);
    QByteArray decodeTransforms(QByteArray input);
private:
    QMutex m_transformMutex;
};
