#include "scripttrigger.h"
#include <QMutexLocker>
#include <algorithm>

// gui.exe:0x140109EB0, helper0x1401073A0. Its once-list is embedded here.
ScriptTrigger::ScriptTrigger(const QSharedPointer<ScriptRunner> &runner,
                             NativeScriptCatalogPort &catalog, QObject *parent)
    : QObject(parent), m_runner(runner), m_catalog(catalog) {}

// gui.exe:0x14010A750 + 0x14010C400; no native mutex around replacement.
void ScriptTrigger::setScripts(const QStringList &selections)
{
    QHash<quint64, QList<ScriptURI>> scripts;
    for (const QString &selection : selections) {
        const ScriptURI resolved = m_catalog.resolve(ScriptURI(selection));
        for (quint64 trigger : resolved.triggers)
            scripts[trigger].append(resolved);
    }
    for (auto &bucket : scripts)
        std::sort(bucket.begin(), bucket.end(), [](const ScriptURI &a, const ScriptURI &b) {
            return a.priority < b.priority; // signed comparator, 0x140107640
        });
    m_scripts = std::move(scripts);
}

// gui.exe:0x14010AEB0; lookup0x14010CA40 hashes only Event.type.
qsizetype ScriptTrigger::emitEvent(Event event, NetworkResponsePtr response,
                                   ParameterInjectionPtr parameter)
{
    QList<ScriptURI> scripts;
    {
        QMutexLocker locker(&m_mutex);
        scripts = m_scripts.value(event.type);
    }
    if (scripts.isEmpty())
        return 0;
    m_runner->enqueue(ScriptWorkItem{response, parameter, event}, scripts);
    return scripts.size();
}

// gui.exe:0x14010ACA0. Explicit descriptor bypasses the trigger lookup.
bool ScriptTrigger::emitScript(const ScriptURI &script, Event event,
                               NetworkResponsePtr response, ParameterInjectionPtr parameter)
{
    m_runner->enqueue(ScriptWorkItem{response, parameter, event}, QList<ScriptURI>{script});
    return true;
}

// gui.exe:0x14010B3C0. Source value copy replaces the native optional reference.
std::optional<ScriptURI> ScriptTrigger::findScript(const QString &name)
{
    QMutexLocker locker(&m_mutex);
    for (const auto &bucket : m_scripts)
        for (const auto &script : bucket)
            if (script.name == name)
                return script;
    return std::nullopt;
}

// gui.exe:0x14010B200.
bool ScriptTrigger::emitScript(const QString &name, Event event,
                               NetworkResponsePtr response, ParameterInjectionPtr parameter)
{
    const auto script = findScript(name);
    if (!script)
        return false;
    return emitScript(*script, event, response, parameter);
}

// gui.exe:0x1401074E0/0x140107580. A failed dispatch still consumes its hash.
qint32 ScriptTrigger::emitOnce(Event &event, NetworkResponsePtr response,
                               ParameterInjectionPtr parameter)
{
    const quint64 hash = event.identityHash();
    if (m_onceHashes.contains(hash))
        return -1;
    m_onceHashes.append(hash);
    const qsizetype count = emitEvent(event, response, parameter);
    return count > 0 ? static_cast<qint32>(count) : 0;
}

qint32 ScriptTrigger::emitOnce(QString name, Event &event, NetworkResponsePtr response,
                               ParameterInjectionPtr parameter)
{
    const quint64 hash = event.identityHash();
    if (m_onceHashes.contains(hash))
        return -1;
    m_onceHashes.append(hash);
    return emitScript(name, event, response, parameter) ? 1 : 0;
}
