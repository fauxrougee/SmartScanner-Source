#include "httpheadercheck.h"
#include "httpissuecapture.h"

#include "issue.h"
#include "issuedb.h"
#include "issuetemplate.h"
#include "urlnormalizer.h"

#include <QNetworkRequest>
#include <QNetworkCookie>
#include <QRegularExpression>

namespace {

QByteArray headerValue(const HttpResponse &response, const QByteArray &name,
                       bool *present = nullptr)
{
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray headerName = response.raw.mid(range.name.offset,
                                                       range.name.length);
        if (headerName.compare(name, Qt::CaseInsensitive) == 0) {
            if (present)
                *present = true;
            return response.raw.mid(range.value.offset, range.value.length);
        }
    }
    // GUI NetworkManager::responseFromReply retains header-pair ranges into
    // `raw` at field120. The native test has no second lookup source, so an
    // empty field120 means absent.
    if (present)
        *present = false;
    return {};
}

QList<QByteArray> headerValues(const HttpResponse &response, const QByteArray &name)
{
    QList<QByteArray> values;
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray headerName = response.raw.mid(range.name.offset,
                                                       range.name.length);
        if (headerName.compare(name, Qt::CaseInsensitive) == 0) {
            values.append(response.raw.mid(range.value.offset, range.value.length));
        }
    }
    return values;
}

bool nativeResponseIsEligible(const HttpResponse &response)
{
    // gui.exe:0x14007D6A0, translated against the recovered response model.
    const qint32 state = static_cast<qint32>(response.error);
    const bool stateAllowed = ((state - 1) & 0xfa) != 0 || state == 2;
    const qint64 requestKind = response.request.attribute(
        static_cast<QNetworkRequest::Attribute>(1012)).toLongLong();
    return response.statusCode > 0 && stateAllowed
        && (response.statusCode < 400 || response.statusCode > 499)
        && !response.field170 && (requestKind == 1 || requestKind == 2);
}

bool htmlResponse(const HttpResponse &response)
{
    // gui.exe:0x140082630: case-insensitive header name, trim/lower value,
    // then prefix comparison with literal `text/html`.
    return headerValue(response, QByteArrayLiteral("Content-Type")).trimmed()
        .toLower().startsWith(QByteArrayLiteral("text/html"));
}

bool bodyStartsWithKnownEncodingMark(const QByteArray &body)
{
    // gui.exe:0x140081DD0. The byte sequences are constructed there through
    // QByteArray::fromHex and tested in this exact order.
    static const QList<QByteArray> marks = {
        QByteArray::fromHex("EFBBBF"), QByteArray::fromHex("FEFF"),
        QByteArray::fromHex("FFFE"), QByteArray::fromHex("0000FEFF"),
        QByteArray::fromHex("FFFE0000"), QByteArray::fromHex("2B2F7638"),
        QByteArray::fromHex("2B2F7639"), QByteArray::fromHex("2B2F762B"),
        QByteArray::fromHex("2B2F762F"), QByteArray::fromHex("2B2F76382D"),
        QByteArray::fromHex("F7644C"), QByteArray::fromHex("DD736673"),
        QByteArray::fromHex("0EFEFF"), QByteArray::fromHex("FBEE28"),
        QByteArray::fromHex("84319533")};
    for (const QByteArray &mark : marks) {
        if (body.startsWith(mark))
            return true;
    }
    return false;
}

QString referrerPolicy(const HttpResponse &response)
{
    bool headerPresent = false;
    const QByteArray header = headerValue(response, QByteArrayLiteral("Referrer-Policy"),
                                          &headerPresent);
    if (headerPresent)
        return QString::fromUtf8(header);

    // gui.exe:0x140082F00 -> 0x1401376F0. It finds the first `meta` whose
    // `name` is `referrer`, then extracts that element's `content` attribute.
    const QString document = QString::fromUtf8(
        response.raw.mid(response.bodyOffset, response.bodyLength));
    const QString name = QStringLiteral("name");
    const QString value = QStringLiteral("referrer");
    const QString elementPattern = QStringLiteral("<meta\\s+[^>]*?\\b")
        + QRegularExpression::escape(name)
        + QStringLiteral("\\s*=\\s*['\"]?")
        + QRegularExpression::escape(value)
        + QStringLiteral("['\"]?[^>]*?>");
    const QRegularExpression elementExpression(
        elementPattern, QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch element = elementExpression.match(document);
    if (!element.hasMatch())
        return {};

    const QRegularExpression contentExpression(
        QRegularExpression::escape(QStringLiteral("content"))
        + QStringLiteral("\\s*=\\s*(?(?=[\"'])(['\"])([\\s\\S]*?)\\1|([^\\s>]+))"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch content = contentExpression.match(element.captured(0));
    if (!content.hasMatch())
        return {};
    const QString quoted = content.captured(2);
    return quoted.isNull() ? content.captured(3) : quoted;
}

void setNativeIdentity(Issue *issue, const HttpResponse &response,
                       const QString &suffix);

void attachNativeHttpCapture(Issue *issue, const HttpResponse &response)
{
    // gui.exe:0x14007D330 obtains both buffers, attaches them to the Issue,
    // then submits the IssueDb entry.  The recovered Issue storage is fieldF0.
    issue->fieldF0.append(qMakePair(nativeIssueRequestCapture(response.request),
                                    nativeIssueResponseCapture(response)));
}

void addIssue(IssueDb *issueDb, const HttpResponse &response,
              const QString &genericIssueDataPath, const QString &name,
              const qint32 impact, const QString &identitySuffix)
{
    Issue issue;
    IssueTemplate::applyGeneric(&issue, name, genericIssueDataPath);
    // The compiled handlers write these after 0x140046D70.
    issue.field18 = name;
    issue.field30 = response.url;
    issue.field38 = impact;
    setNativeIdentity(&issue, response, identitySuffix);
    attachNativeHttpCapture(&issue, response);
    issueDb->add(std::move(issue));
}

bool isSessionCookie(const QByteArray &name, const QByteArray &value)
{
    // gui.exe:0x140082790.  The PHP name comparison is case-sensitive; the
    // two named-pattern checks are case-insensitive, while the 26-character
    // value expression retains its native case-sensitive option.
    if (name == QByteArrayLiteral("PHPSESSID"))
        return true;
    if (QRegularExpression(QStringLiteral("SESSION"),
                           QRegularExpression::CaseInsensitiveOption)
            .match(QString::fromUtf8(name)).hasMatch()) {
        return true;
    }
    if (QRegularExpression(QStringLiteral("^[a-z0-9]{26}$"))
            .match(QString::fromUtf8(value)).hasMatch()) {
        return true;
    }
    if (QRegularExpression(QStringLiteral("csrf|anti|xsrf"),
                           QRegularExpression::CaseInsensitiveOption)
            .match(QString::fromUtf8(name)).hasMatch()) {
        return false;
    }
    // sub_1400831B0 expands `[md5]` to this case-insensitive expression.
    return QRegularExpression(QStringLiteral("^[a-f0-9]{32}$"),
                              QRegularExpression::CaseInsensitiveOption)
        .match(QString::fromUtf8(value)).hasMatch();
}

void setNativeIdentity(Issue *issue, const HttpResponse &response,
                       const QString &suffix)
{
    // gui.exe:0x140082530 / 0x140057D60 replaces Issue's ordinary identity
    // with qHash(canonical(url, 110) + "@" + the rule-local suffix).
    issue->field250 = qHash(QStringView(UrlNormalizer::canonical(response.url, 110)
                                        + QLatin1Char('@') + suffix), 0);
    issue->field258 = true;
}

void addCookieIssue(IssueDb *issueDb, const HttpResponse &response,
                    const QString &genericIssueDataPath, const QString &name,
                    qint32 impact, const QByteArray &cookie,
                    const QString &identitySuffix)
{
    Issue issue;
    IssueTemplate::applyGeneric(&issue, name, genericIssueDataPath);
    issue.field18 = name;
    issue.field30 = response.url;
    issue.field38 = impact;
    issue.field108[QStringLiteral("Cookie")].insert(QString::fromUtf8(cookie));
    setNativeIdentity(&issue, response, identitySuffix);
    attachNativeHttpCapture(&issue, response);
    issueDb->add(std::move(issue));
}

} // namespace

void HttpHeaderCheck::process(const NetworkManager::ResponsePointer &response,
                              IssueDb *issueDb, const QString &selection,
                              const QString &genericIssueDataPath)
{
    if (!response || !issueDb)
        return;

    const qint32 flags = response->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    // First branch of gui.exe:0x140081760 / sub_14013ED60(response, 8).
    if ((flags & 8) != 8)
        return;

    const bool others = selection.indexOf(QStringLiteral("others"), 0,
                                          Qt::CaseSensitive) != -1;
    const bool owasp = selection.indexOf(QStringLiteral("owasp"), 0,
                                         Qt::CaseSensitive) != -1;
    if (!others && !owasp)
        return;

    if (others && nativeResponseIsEligible(*response)) {
    if (htmlResponse(*response)) {
        bool hasFrameOptions = false;
        headerValue(*response, QByteArrayLiteral("X-Frame-Options"), &hasFrameOptions);
        if (!hasFrameOptions) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("X-Frame-Options Header is Missing"), 3,
                     QStringLiteral("X-Frame-Options@missHeader"));
        }

        bool hasXssProtection = false;
        const QByteArray xssProtection = headerValue(
            *response, QByteArrayLiteral("X-XSS-Protection"), &hasXssProtection);
        // gui.exe:0x140081380: a present header only; after trimming, exact
        // `0` suppresses the Information-impact report.
        if (hasXssProtection && xssProtection.trimmed() != QByteArrayLiteral("0")) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("X-XSS-Protection Header is Set"), 4,
                     QStringLiteral("X-XSS-Protection@missHeader"));
        }

    }

    // gui.exe:0x14007FDB0 is deliberately outside the HTML-only rules and is
    // called between the XSS and CSP branches at 0x140081946--0x14008194E.
    bool hasHsts = false;
    headerValue(*response, QByteArrayLiteral("Strict-Transport-Security"), &hasHsts);
    if (response->url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0
        && !hasHsts) {
        addIssue(issueDb, *response, genericIssueDataPath,
                 QStringLiteral("Strict-Transport-Security Header is Missing"), 3,
                 QStringLiteral("Strict-Transport-Security@missHeader"));
    }

    if (htmlResponse(*response)) {
        bool hasCsp = false;
        headerValue(*response, QByteArrayLiteral("Content-Security-Policy"), &hasCsp);
        if (!hasCsp) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Content-Security-Policy Header is Missing"), 3,
                     QStringLiteral("Content-Security-Policy@missHeader"));
        }
    }

    // gui.exe:0x14007EE10 checks this rule for every eligible response. Its
    // lower-case comparison is exact and does not trim the header value.
    const QByteArray contentTypeOptions = headerValue(
        *response, QByteArrayLiteral("X-Content-Type-Options"));
    if (contentTypeOptions.toLower() != QByteArrayLiteral("nosniff")) {
        addIssue(issueDb, *response, genericIssueDataPath,
                 QStringLiteral("X-Content-Type-Options Header is Missing"), 4,
                 QStringLiteral("X-Content-Type-Options@missHeader"));
    }

    // gui.exe:0x14007E920. The header/body searches for literal `charset=`
    // are case-sensitive; a known leading encoding mark suppresses the issue.
    const QByteArray contentType = headerValue(*response, QByteArrayLiteral("Content-Type"));
    const QByteArray body = response->raw.mid(response->bodyOffset,
                                               response->bodyLength);
    if (contentType.trimmed().toLower().startsWith(QByteArrayLiteral("text"))
        && !body.trimmed().isEmpty()
        && !contentType.contains(QByteArrayLiteral("charset="))
        && !body.contains(QByteArrayLiteral("charset="))
        && !bodyStartsWithKnownEncodingMark(body)) {
        addIssue(issueDb, *response, genericIssueDataPath,
                 QStringLiteral("Content Character Encoding is not Defined"), 4,
                 QStringLiteral("Content-Type@noCharSet"));
    }

    // gui.exe:0x14007F0D0.  SameSite is checked on each raw Set-Cookie
    // header before Qt parses it; HttpOnly and Secure are then checked on
    // every QNetworkCookie parsed from that same header.
    const QList<QByteArray> setCookies = headerValues(*response,
                                                      QByteArrayLiteral("Set-Cookie"));
    const QRegularExpression sameSiteExpression(
        QStringLiteral("; SameSite=([^\\s;]+?)"),
        QRegularExpression::CaseInsensitiveOption);
    for (const QByteArray &setCookie : setCookies) {
        const QRegularExpressionMatch sameSite = sameSiteExpression.match(
            QString::fromUtf8(setCookie));
        if (!sameSite.hasMatch()
            || sameSite.captured(1).toLower() == QStringLiteral("none")) {
            const QByteArray pair = setCookie.left(setCookie.indexOf(';'));
            const qsizetype equals = pair.indexOf('=');
            const QByteArray cookieName = pair.left(equals);
            const QByteArray cookieValue = pair.mid(equals + 1);
            const bool session = isSessionCookie(cookieName, cookieValue);
            addCookieIssue(issueDb, *response, genericIssueDataPath,
                           session ? QStringLiteral("Session Cookie without SameSite Flag")
                                   : QStringLiteral("Cookie without SameSite Flag"),
                           session ? 2 : 3, pair,
                           QString::fromUtf8(cookieName)
                               + QStringLiteral("@noSameSite"));
        }

        const QList<QNetworkCookie> parsedCookies = QNetworkCookie::parseCookies(setCookie);
        for (const QNetworkCookie &cookie : parsedCookies) {
            const bool session = isSessionCookie(cookie.name(), cookie.value());
            const QByteArray rawCookie = cookie.toRawForm(QNetworkCookie::Full);
            if (!cookie.isHttpOnly()) {
                addCookieIssue(issueDb, *response, genericIssueDataPath,
                               session ? QStringLiteral("Session Cookie without HttpOnly Flag")
                                       : QStringLiteral("Cookie without HttpOnly Flag"),
                               session ? 2 : 3, rawCookie,
                               QString::fromUtf8(cookie.name())
                                   + QStringLiteral("@noHttpOnly"));
            }
            if (!cookie.isSecure()) {
                addCookieIssue(issueDb, *response, genericIssueDataPath,
                               session ? QStringLiteral("Session Cookie without Secure Flag")
                                       : QStringLiteral("Cookie without Secure Flag"),
                               session ? 2 : 3, rawCookie,
                               QString::fromUtf8(cookie.name())
                                   + QStringLiteral("@noSecure"));
            }
        }
    }

    // gui.exe:0x140080000. A present HPKP header is retained verbatim in the
    // issue custom-field set under literal key `HPKP`.
    bool hasHpkp = false;
    const QByteArray hpkp = headerValue(*response, QByteArrayLiteral("Public-Key-Pins"),
                                        &hasHpkp);
    if (hasHpkp) {
        Issue issue;
        IssueTemplate::applyGeneric(&issue,
                                    QStringLiteral("Public-Key-Pins Header is Set"),
                                    genericIssueDataPath);
        issue.field18 = QStringLiteral("Public-Key-Pins Header is Set");
        issue.field30 = response->url;
        issue.field38 = 4;
        issue.field108[QStringLiteral("HPKP")].insert(QString::fromUtf8(hpkp));
        setNativeIdentity(&issue, *response,
                          QStringLiteral("Public-Key-Pins@Header"));
        attachNativeHttpCapture(&issue, *response);
        issueDb->add(std::move(issue));
    }

    // gui.exe:0x140080AC0. This is HTML-only and uses a lower-case policy
    // string; every non-empty policy except one starting `unsafe-url` avoids
    // the Information-impact report.
    if (htmlResponse(*response)) {
        const QString policy = referrerPolicy(*response).toLower();
        if (policy.isEmpty() || policy.startsWith(QStringLiteral("unsafe-url"))) {
            addIssue(issueDb, *response, genericIssueDataPath,
                     QStringLiteral("Referrer-Policy Header is Missing"), 4,
                     QStringLiteral("Referrer-Policy@noHeader"));
        }
    }

    // gui.exe:0x14007F2F0. The initial lookup is case-sensitive, so a header
    // spelled with any other casing is deliberately ignored. The later lookup
    // obtains the value case-insensitively, trims it, then accepts only `*`.
    bool exactCorsHeader = false;
    for (const HttpResponse::HeaderRange &range : response->field120) {
        if (response->raw.mid(range.name.offset, range.name.length)
            == QByteArrayLiteral("Access-Control-Allow-Origin")) {
            exactCorsHeader = true;
            break;
        }
    }
    if (exactCorsHeader
        && headerValue(*response, QByteArrayLiteral("Access-Control-Allow-Origin"))
               .trimmed() == QByteArrayLiteral("*")) {
        Issue issue;
        const QString name = QStringLiteral("Cross-Origin Resource Sharing Allowed");
        IssueTemplate::applyGeneric(&issue, name, genericIssueDataPath);
        issue.field18 = name;
        issue.field30 = response->url;
        issue.field38 = 4;
        setNativeIdentity(&issue, *response,
                          QStringLiteral("Access-Control-Allow-Origin"));
        attachNativeHttpCapture(&issue, *response);
        issueDb->add(std::move(issue));
    }
    }

    // gui.exe:0x140080500, reached from the independent, case-sensitive
    // `owasp` selection branch at 0x140081AB3. It intentionally has no
    // 0x14007D6A0 eligibility gate. As with the CORS branch, the initial
    // header-name lookup is exact-case.
    if (owasp) {
        bool exactPoweredByHeader = false;
        for (const HttpResponse::HeaderRange &range : response->field120) {
            if (response->raw.mid(range.name.offset, range.name.length)
                == QByteArrayLiteral("X-Powered-By")) {
                exactPoweredByHeader = true;
                break;
            }
        }
        if (exactPoweredByHeader) {
            const QByteArray poweredBy = headerValue(*response,
                                                     QByteArrayLiteral("X-Powered-By"));
            Issue issue;
            const QString name = QStringLiteral("X-Powered-By Header Found");
            IssueTemplate::applyGeneric(&issue, name, genericIssueDataPath);
            issue.field18 = name;
            issue.field30 = response->url;
            issue.field38 = 4;
            const QByteArray identity = UrlNormalizer::canonical(response->url, 110)
                                            .toUtf8()
                + QByteArrayLiteral("@poweredBy@") + poweredBy;
            issue.field250 = qHash(QByteArrayView(identity), 0);
            issue.field258 = true;
            attachNativeHttpCapture(&issue, *response);
            issueDb->add(std::move(issue));
        }
    }
}
