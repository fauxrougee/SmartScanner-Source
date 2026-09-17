#pragma once
#include "scriptrunner.h"
#include <QStringList>
#include <optional>

class ScriptTrigger final : public QObject {
    Q_OBJECT
public:
    // catalog reference is a source adapter for the native singleton.
    ScriptTrigger(const QSharedPointer<ScriptRunner> &runner,
                  NativeScriptCatalogPort &catalog, QObject *parent = nullptr);
    void setScripts(const QStringList &selections);
    // Native helper +48, ctor0x1401073A0, emits once per Event hash. Not thread-safe.
    qint32 emitOnce(Event &event, NetworkResponsePtr response = {},
                    ParameterInjectionPtr parameter = {});
    qint32 emitOnce(QString name, Event &event, NetworkResponsePtr response = {},
                    ParameterInjectionPtr parameter = {});
public slots:
    qsizetype emitEvent(Event event, NetworkResponsePtr response = {},
                        ParameterInjectionPtr parameter = {});
    bool emitScript(const ScriptURI &script, Event event,
                    NetworkResponsePtr response = {}, ParameterInjectionPtr parameter = {});
    bool emitScript(const QString &name, Event event,
                    NetworkResponsePtr response = {}, ParameterInjectionPtr parameter = {});
private:
    friend struct ScriptTriggerTestAccess;
    std::optional<ScriptURI> findScript(const QString &name);
    QMutex m_mutex;
    QSharedPointer<ScriptRunner> m_runner;
    QHash<quint64, QList<ScriptURI>> m_scripts;
    NativeScriptCatalogPort &m_catalog;
    QList<quint64> m_onceHashes;
};
