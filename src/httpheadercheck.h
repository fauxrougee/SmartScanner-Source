#pragma once

#include "networkmanager.h"

#include <QString>

class IssueDb;

// Compiled `httpheaders` test recovered from gui.exe:0x140081760.  This is
// deliberately a concrete class, not a speculative generic Test interface.
class HttpHeaderCheck final
{
public:
    // `selection` is the native TestScript QString at +0x58, for example
    // `httpheaders@o=owasp,others`.
    static void process(const NetworkManager::ResponsePointer &response,
                        IssueDb *issueDb, const QString &selection,
                        const QString &genericIssueDataPath);
};
