#include "secretleakfinding.h"

#include "httpclient.h"
#include "issue.h"
#include "issuedb.h"
#include "issuetemplate.h"
#include "urlnormalizer.h"

#include <QMutexLocker>

bool secretLeakProcessResponse(const HttpResponse *response, IssueDb *issueDb,
                               const SecretLeakConfig &config,
                               const QString &genericIssueDataPath)
{
    // 0x140045651-0x140045658: null retained response.
    if (!response || !issueDb)
        return false;
    // 0x140045662: *(int *)(response + 16) > 0 (status code).
    if (response->statusCode <= 0)
        return false;
    // 0x140045668-0x140045679: byte at response + 48, same predicate as
    // gui.exe:0x14007D6A0; rejects states 1, 5 and 6.
    const qint32 state = static_cast<quint8>(response->error);
    if (!(((state - 1) & 0xfa) != 0 || state == 2))
        return false;

    // 0x140045683: sub_140043A70 -> QByteArray(sub_1400438E0(response)).
    // TODO(REVERSE): 0x1400438E0 is assumed to return the body view, as the
    // other GUI tests use raw.mid(bodyOffset, bodyLength); decompile it to
    // confirm the range.
    const QByteArray body = response->raw.mid(response->bodyOffset, response->bodyLength);
    // 0x14004569E: QUrl::toString(response + 8, 0); 0x1400456AA: QString(body).
    const QString url = response->url.toString(QUrl::None);
    const QString bodyText = QString::fromUtf8(body);
    // 0x1400456C5: sub_140054490(&qword_140360C88, &records, body, url).
    const QList<SecretLeakMatchRecord> records = secretLeakMatches(config, bodyText, url);

    // 0x140045709: only the first 112-byte record produces an Issue.
    if (records.isEmpty())
        return false;
    const SecretLeakMatchRecord first = records.first();

    // 0x140045765-0x1400457EA: qHash(QStringView(canonical(url, 110)
    // + record+72), 0).  No separator is inserted.
    const quint64 identity = qHash(
        QStringView(UrlNormalizer::canonical(response->url, 110) + first.selectedCapture), 0);

    // 0x140045833-0x140045847: QUrl(QUrl::toString(4326), TolerantMode).
    // 4326 = 0x10E6 = RemoveUserInfo | RemovePath | RemoveQuery
    //                 | RemoveFragment | NormalizePathSegments.
    const QUrl issueUrl(response->url.toString(QUrl::FormattingOptions(4326)),
                        QUrl::TolerantMode);

    Issue issue;
    const QString name = QStringLiteral("Sensitive Data Disclosure");
    // 0x14004586A: sub_140046D70(issue, name).
    IssueTemplate::applyGeneric(&issue, name, genericIssueDataPath);
    issue.field18 = name;            // 0x140045879
    issue.field30 = issueUrl;        // 0x14004588D
    issue.field38 = 2;               // 0x140045893
    {
        // 0x1400458B5-0x1400458D5.
        QMutexLocker<QRecursiveMutex> lock(&issue.field238);
        issue.field250 = identity;
        issue.field258 = true;
    }
    {
        // 0x1400458F8-0x140045914: +0x110 = 1 under the same mutex.
        QMutexLocker<QRecursiveMutex> lock(&issue.field238);
        issue.field110 = 1;
    }
    // 0x14004592A-0x140045939: copy (0x1400217F0), then
    // sub_1401257B0(issueDb, copy, 0).  No request/response capture is
    // attached by this slot (no 0x14007D330 call).
    issueDb->add(issue, false);
    return true;
}
