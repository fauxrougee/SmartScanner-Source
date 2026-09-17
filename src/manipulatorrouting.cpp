#include "manipulatorrouting.h"

ManipulatorRoutingPlan manipulatorRoutingPlan(
    bool hasResponse, int enabledFlags, const QUrl &responseUrl) noexcept
{
    // gui.exe:0x140113770. The response pointer guards every branch. Bit 1
    // additionally requires QUrl::hasQuery(); the native then builds
    // QUrlQuery instances from the URL and request attribute 1003.
    if (!hasResponse)
        return {};

    return {
        (enabledFlags & 0x01) != 0 && responseUrl.hasQuery(),
        (enabledFlags & 0x02) != 0,
        (enabledFlags & 0x04) != 0,
        (enabledFlags & 0x08) != 0,
        (enabledFlags & 0x10) != 0,
    };
}
