#include "custom404cachedecision.h"

#include "custom404bodycache.h"
#include "custom404scopematcher.h"
#include "custom404similarity.h"

int custom404CachedBodyDecision(const QByteArray &responseBody, const QUrl &url,
                                bool matchesRetainedBody,
                                const QHash<quint64, QByteArray> &directoryBodies,
                                const QStringList &storedScopes)
{
    // gui.exe:0x14014F1A0. `matchesRetainedBody` is the preceding call to
    // 0x14014D930; response-body acquisition at 0x140043A70 is intentionally
    // supplied by the caller rather than reconstructed here.
    if (matchesRetainedBody)
        return -2;

    QUrl rootUrl(url);
    rootUrl.setPath(QStringLiteral("/"), QUrl::DecodedMode);
    const QByteArray rootBody = custom404LookupDirectoryBody(directoryBodies, rootUrl);
    if (rootBody.isNull())
        return 3;
    if (Custom404Similarity::score(responseBody, rootBody) > 90.0)
        return 0;

    const QByteArray directoryBody = custom404LookupDirectoryBody(directoryBodies, url);
    if (directoryBody.isNull())
        return 3;
    if (Custom404Similarity::score(responseBody, directoryBody) > 90.0)
        return 0;

    return custom404MatchesStoredScope(url.toString(), storedScopes) ? -2 : 1;
}
