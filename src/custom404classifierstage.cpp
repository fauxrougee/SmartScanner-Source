#include "custom404classifierstage.h"

#include "custom404cachedecision.h"
#include "custom404errorevidence.h"
#include "custom404responsebypass.h"
#include "httpclient.h"

namespace {

QByteArray headerValue(const HttpResponse &response, const QByteArray &wanted)
{
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray name = response.raw.mid(range.name.offset, range.name.length);
        if (name.compare(wanted, Qt::CaseInsensitive) == 0)
            return response.raw.mid(range.value.offset, range.value.length);
    }
    return {};
}

QByteArray bodyBytes(const HttpResponse &response)
{
    return response.raw.mid(response.bodyOffset, response.bodyLength);
}

} // namespace

int custom404ClassifyNonExceptionalResponse(
    const HttpResponse &response, bool matchesRetainedBody,
    const QHash<quint64, QByteArray> &directoryBodies,
    const QStringList &storedScopes)
{
    // gui.exe:0x14014DEF0 after the fixed 401/4xx/5xx status routes.
    if (!custom404ResponseBypassesErrorEvidence(response)
        && custom404HasErrorEvidence(response)) {
        return 0;
    }

    // gui.exe:0x14008AB70: a lower-case `location` header is converted to a
    // QString then parsed by QUrl with parsing mode 0 (TolerantMode).
    const QUrl location(QString::fromUtf8(headerValue(response, QByteArrayLiteral("location"))),
                        QUrl::TolerantMode);
    if (location.isValid())
        return 3;

    return custom404CachedBodyDecision(bodyBytes(response), response.url,
                                       matchesRetainedBody, directoryBodies,
                                       storedScopes);
}
