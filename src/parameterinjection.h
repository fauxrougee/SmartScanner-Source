#pragma once
#include "parameter.h"
#include "injectionvector.h"
#include "basicparameter.h"
#include <QNetworkRequest>

// Partial source-level ParameterInjection. Recovers the observed virtual path;
// embedded parser state at native +88 and its operations remain unimplemented.
// Flattened arguments replace native packed records; label maps +56/+32 to1013.
class ParameterInjection : public Parameter {
public:
    ParameterInjection(qint32 kind, const QSharedPointer<InjectionVector> &vector,
                       const QString &name, const QString &value);
    bool isValid() const override;
    QString value(const QString &fallback = QString(), qint32 mode = 0) const override;
    void setValue(const QString &value, qint32 mode = 0) override;
    virtual QNetworkRequest apply(qint32 flags, const QByteArray &value,
        const QString &name, const QString &label, QNetworkRequest base);
    virtual QNetworkRequest apply(qint32 flags, qint32 value,
        const QString &name, const QString &label, QNetworkRequest base);
    virtual QNetworkRequest apply(qint32 flags, const QString &value,
        const QString &name, const QString &label, QNetworkRequest base);
protected:
    friend class Manipulator;
    friend QString describeScriptParameter(const QSharedPointer<ParameterInjection> &);
    virtual QNetworkRequest applyVariant(const QVariant &injection, QNetworkRequest base) = 0;
    QSharedPointer<InjectionVector> m_vector;
};

// Native RTTI labels, with the observed slot11 implemented in separate files.
// Inherited construction exposes recovered base state only, not native factories.
class HeaderParameterInjection final : public ParameterInjection {
public: using ParameterInjection::ParameterInjection;
    HeaderParameterInjection(const QSharedPointer<InjectionVector> &, const QString &, const QString &);
protected: QNetworkRequest applyVariant(const QVariant &, QNetworkRequest) override;
};
class QueryParameterInjection final : public ParameterInjection {
public: using ParameterInjection::ParameterInjection;
    QueryParameterInjection(const QSharedPointer<InjectionVector> &, const QString &, const QString &);
protected: QNetworkRequest applyVariant(const QVariant &, QNetworkRequest) override;
};
class UrlParameterInjection final : public ParameterInjection {
public: using ParameterInjection::ParameterInjection;
    UrlParameterInjection(const QSharedPointer<InjectionVector> &, const QString &, const QString &);
protected: QNetworkRequest applyVariant(const QVariant &, QNetworkRequest) override;
};
class PostParameterInjection final : public ParameterInjection {
public: using ParameterInjection::ParameterInjection;
    PostParameterInjection(const QSharedPointer<InjectionVector> &, const QString &, const QString &);
protected: QNetworkRequest applyVariant(const QVariant &, QNetworkRequest) override;
};
class CookieParameterInjection final : public ParameterInjection {
public: using ParameterInjection::ParameterInjection;
    CookieParameterInjection(const QSharedPointer<InjectionVector> &, const QString &, const QString &);
protected: QNetworkRequest applyVariant(const QVariant &, QNetworkRequest) override;
};
