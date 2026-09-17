#include "requestmanagermaintenance.h"

bool requestManagerShouldCollectReply(
    qsizetype trackedReplyCount, qint64 nowMilliseconds,
    qint64 requestStartedMilliseconds, qint64 replyDurationMilliseconds,
    int requestAttribute1011) noexcept
{
    // sms.exe:0x1401341C8. The duration is a QObject dynamic property and
    // start time is native request attribute 1001.
    return trackedReplyCount > 50
           || nowMilliseconds - (replyDurationMilliseconds + requestStartedMilliseconds)
                  >= 3000
           || (requestAttribute1011 & 0x100) != 0;
}

bool requestManagerReplyTimedOut(
    qint64 nowMilliseconds, qint64 requestStartedMilliseconds,
    qint64 timeoutMilliseconds) noexcept
{
    // sms.exe:0x14013449D uses a strict comparison, not >=.
    return nowMilliseconds - requestStartedMilliseconds > timeoutMilliseconds;
}
