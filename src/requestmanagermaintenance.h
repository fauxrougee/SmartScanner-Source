#pragma once

#include <QtGlobal>

// Pure branches from the periodic RequestManager slot at
// sms.exe:0x140134000. The native container removals and QNetworkReply abort
// calls remain owned by the manager's unrecovered reply-table representation.
[[nodiscard]] bool requestManagerShouldCollectReply(
    qsizetype trackedReplyCount, qint64 nowMilliseconds,
    qint64 requestStartedMilliseconds, qint64 replyDurationMilliseconds,
    int requestAttribute1011) noexcept;

[[nodiscard]] bool requestManagerReplyTimedOut(
    qint64 nowMilliseconds, qint64 requestStartedMilliseconds,
    qint64 timeoutMilliseconds) noexcept;
