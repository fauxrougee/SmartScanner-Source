#pragma once

#include "injectionvector.h"
#include <QList>
#include <QMutex>
#include <QPair>
#include <QRecursiveMutex>
#include <QSharedPointer>
#include <QString>
#include <QVariant>

// Name preserved in RTTI; methods below are reconstruction labels. Only the
// five virtual operations and constructor-observed state are in this component.
class UrlEncodedInjectionVector final : public InjectionVector {
public:
    using QueryItems = QList<QPair<QString, QString>>;
    UrlEncodedInjectionVector(const QueryItems &items, qint32 selectedIndex);
    [[nodiscard]] bool isValid() const override;
    [[nodiscard]] qint32 supportedFlagsRaw() const override;
    QVariant apply(qint32 flags, const QString &value, const QString &name) override;
    QVariant apply(qint32 flags, const QByteArray &value, const QString &name) override;
    QVariant apply(qint32 flags, qint32 value, const QString &name) override;

private:
    mutable QRecursiveMutex m_mutex;
    QueryItems m_items; // native +64
    qint32 m_selectedIndex; // native +88
};
