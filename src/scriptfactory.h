#pragma once

#include "scriptnativeports.h"

#include <QHash>
#include <QList>
#include <QMutex>

#include <functional>

// SOURCE ADAPTERS. These names and containers are reconstructed equivalents,
// not original Factory declarations or ABI layouts. gui.exe:0x140105400,
// 0x140105EC0, 0x1401064C0 and 0x140106560 establish the transitions below.
class ScriptFactoryDependencyBinder {
public:
    virtual ~ScriptFactoryDependencyBinder() = default;
    // The native creation path binds six dependencies immediately after the
    // factory callback returns. Concrete reconstructed types remain pending.
    virtual void bind(const QSharedPointer<NativeScriptInstancePort> &) const = 0;
};

struct ScriptFactoryEntry {
    QString name;
    QList<quint64> triggers;
    qint32 priority = -1;
    std::function<QSharedPointer<NativeScriptInstancePort>(const QString &)> make;
};

class ScriptFactory final : public NativeScriptCatalogPort {
public:
    explicit ScriptFactory(const ScriptFactoryDependencyBinder &binder);

    // gui.exe:0x1401064C0: register under qHash(QStringView(name), 0)+10,
    // and index the exact name. QHash::insert has the observed replacement
    // semantics of the native map assignment.
    bool registerEntry(ScriptFactoryEntry entry);
    // gui.exe:0x140106BE0 receives masks then expands every bit through the
    // native trigger table before appending; duplicates remain observable.
    bool appendTriggers(const QString &name, const QList<quint64> &masks);
    bool setPriority(const QString &name, qint32 priority);

    ScriptURI resolve(ScriptURI descriptor) override;
    QSharedPointer<NativeScriptInstancePort> create(const ScriptURI &) override;
    [[nodiscard]] quint64 idForName(const QString &name) const;

    [[nodiscard]] static quint64 keyForName(const QString &name);

private:
    QHash<quint64, ScriptFactoryEntry> m_entries; // native Factory +96
    QHash<QString, quint64> m_names;              // native Factory +104
    const ScriptFactoryDependencyBinder &m_binder;
    mutable QMutex m_mutex;                       // native Factory +88
};
