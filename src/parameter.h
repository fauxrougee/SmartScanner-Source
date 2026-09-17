#pragma once
#include <QRecursiveMutex>
#include <QString>

// Native Parameter base, not the still-incomplete ParameterInjection subclass.
// Method names are reconstructed; the eight operation slots are observed.
class Parameter {
public:
    Parameter(qint32 kind, const QString &name, const QString &value);
    virtual bool isValid() const;
    virtual QString kindName() const;
    virtual QString name() const;
    virtual void setName(const QString &name);
    virtual QString value(const QString &fallback = QString(), qint32 mode = 0) const;
    virtual void setValue(const QString &value, qint32 mode = 0);
    virtual qint32 kind() const;
    virtual void setKind(qint32 kind);
    virtual ~Parameter() = default;
protected:
    mutable QRecursiveMutex m_mutex;
    QString m_name;
    QString m_value;
    qint32 m_kind;
};
