#pragma once

#include <QUrl>

// Direct dispatch gates from gui.exe:0x140113770. The individual injection
// engines selected by these flags have their own unrecovered vector types.
struct ManipulatorRoutingPlan {
    bool urlEncodedParameters = false;
    bool flag2Engine = false;
    bool flag4Engine = false;
    bool flag8Engine = false;
    bool flag16Engine = false;
};

[[nodiscard]] ManipulatorRoutingPlan manipulatorRoutingPlan(
    bool hasResponse, int enabledFlags, const QUrl &responseUrl) noexcept;
