#pragma once
#include "scriptevent.h"
#include "scripturi.h"

#include <QList>

// SOURCE ADAPTERS, not recovered original class declarations. These pure
// boundaries expose proven calls without fabricating the missing script catalog
// or concrete check implementations. No production provider is supplied yet.
class NativeScriptInstancePort {
public:
    virtual ~NativeScriptInstancePort() = default;
    virtual void setResponse(const NetworkResponsePtr &) = 0; // slot+56
    virtual void setParameter(const ParameterInjectionPtr &) = 0; // slot+64
    virtual void setEvent(const Event &) = 0; // slot+72
    virtual void execute() = 0; // slot+88
    virtual quint32 maxInstances() const = 0; // slot+112
    // gui.exe TestScript vtable: 0x140049A30 returns 1 at slot+112;
    // 0x140107100 returns 10 at slot+120; 0x140045BB0 returns an empty
    // QList<quint64> at slot+128. Names are source reconstruction labels.
    virtual quint32 defaultPriority() const = 0;
    virtual QList<quint64> hooks() const = 0;
};
class NativeScriptCatalogPort {
public:
    virtual ~NativeScriptCatalogPort() = default;
    // Calls 0x140105EC0 and 0x140105400 respectively. Production binding,
    // native defaults, factory registry and dependency setters remain pending.
    virtual ScriptURI resolve(ScriptURI descriptor) = 0;
    virtual QSharedPointer<NativeScriptInstancePort> create(const ScriptURI &) = 0;
};
