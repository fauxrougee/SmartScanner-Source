#pragma once
#include "parameterinjection.h"
#include "networkmanager.h"

// Native Qt metadata: Event; hash cache at +40, gui.exe:0x1401073D0.
struct Event {
    quint64 type = 0;
    QVariant data;
    quint64 field28 = 0;
    quint64 identityHash();
};
Q_DECLARE_METATYPE(Event)
using NetworkResponsePtr = NetworkManager::ResponsePointer;
using ParameterInjectionPtr = QSharedPointer<ParameterInjection>;
Q_DECLARE_METATYPE(ParameterInjectionPtr)

// Reconstructed name for native 80-byte work record (0x140114B50).
struct ScriptWorkItem {
    NetworkResponsePtr response;
    ParameterInjectionPtr parameter;
    Event event;
};
QString describeScriptWork(const ScriptWorkItem &work);
QString describeScriptResponse(const NetworkResponsePtr &response);
QString describeScriptParameter(const ParameterInjectionPtr &parameter);
