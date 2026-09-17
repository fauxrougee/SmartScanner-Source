#include "scriptfactory.h"

#include <QDebug>

namespace {
constexpr quint64 kNativeKeyBias = 10;
}

ScriptFactory::ScriptFactory(const ScriptFactoryDependencyBinder &binder)
    : m_binder(binder)
{
}

quint64 ScriptFactory::keyForName(const QString &name)
{
    return qHash(QStringView{name}, 0) + kNativeKeyBias;
}

bool ScriptFactory::registerEntry(ScriptFactoryEntry entry)
{
    const quint64 key = keyForName(entry.name);
    m_entries.insert(key, std::move(entry));
    m_names.insert(m_entries.value(key).name, key);
    return true;
}

bool ScriptFactory::appendTriggers(const QString &name, const QList<quint64> &masks)
{
    const quint64 key = keyForName(name);
    auto found = m_entries.find(key);
    if (found == m_entries.end())
        return true;
    for (const quint64 mask : masks)
        found->triggers.append(ScriptURI::splitTriggerMask(mask));
    return true;
}

bool ScriptFactory::setPriority(const QString &name, qint32 priority)
{
    const quint64 key = keyForName(name);
    auto found = m_entries.find(key);
    if (found != m_entries.end())
        found->priority = priority;
    return true;
}

QSharedPointer<NativeScriptInstancePort> ScriptFactory::create(const ScriptURI &descriptor)
{
    QMutexLocker lock(&m_mutex);
    const auto found = m_entries.constFind(keyForName(descriptor.name));
    if (found == m_entries.cend())
        return {};

    QSharedPointer<NativeScriptInstancePort> instance = found->make(descriptor.options);
    // Native code invokes all dependency setters with no intervening catalog
    // operation. The abstract binder represents that exact phase only.
    m_binder.bind(instance);
    return instance;
}

ScriptURI ScriptFactory::resolve(ScriptURI descriptor)
{
    // gui.exe:0x140105EC0 deliberately performs this lookup without Factory's
    // mutex. ScriptURI parsing already owns the name/options fields by value.
    const auto found = m_entries.find(keyForName(descriptor.name));
    if (found == m_entries.end()) {
        qCritical().noquote() << "Script not found: " << descriptor.toString();
        return descriptor;
    }

    ScriptFactoryEntry &entry = found.value();
    if (descriptor.triggers.isEmpty()) {
        if (entry.triggers.isEmpty()) {
            const QSharedPointer<NativeScriptInstancePort> instance = create(descriptor);
            entry.triggers = instance->hooks();
            entry.priority = static_cast<qint32>(instance->defaultPriority());
        }
        descriptor.triggers = entry.triggers;
        if (descriptor.triggers.isEmpty())
            qCritical().noquote() << "Test has no hooks. It won't run: " << descriptor.toString();
    }
    if (descriptor.priority == -1)
        descriptor.priority = entry.priority;
    return descriptor;
}

quint64 ScriptFactory::idForName(const QString &name) const
{
    QMutexLocker lock(&m_mutex);
    const auto index = m_names.constFind(name.toLower());
    if (index == m_names.cend())
        return quint64(-1);
    const auto entry = m_entries.constFind(index.value());
    if (entry == m_entries.cend())
        return quint64(-1);
    return keyForName(entry->name);
}
