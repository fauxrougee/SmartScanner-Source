#include "custom404probethresholds.h"

#include "custom404urlscope.h"

bool custom404ProbeMatchesPathRoot(const QString &candidateUrl,
                                   const QString &expectedRoot)
{
    // gui.exe:0x14014BC90 -> 0x140150200 -> 0x1400233A0.
    const QUrl parsed(candidateUrl, QUrl::TolerantMode);
    return custom404PathRoot(parsed, custom404PathSlashCount(parsed)) == expectedRoot;
}

bool custom404ProbeMatchesHost(const QString &candidateUrl, const QUrl &expectedUrl)
{
    // gui.exe:0x14014BCF0 -> 0x140150080 -> 0x1400233A0.
    const QUrl parsed(candidateUrl, QUrl::TolerantMode);
    return parsed.host(QUrl::FullyDecoded).toLower()
        == expectedUrl.host(QUrl::FullyDecoded).toLower();
}
