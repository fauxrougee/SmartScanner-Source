#include "cachecontrolrule.h"

#include "httpclient.h"

#include <QNetworkRequest>
#include <QRegularExpression>

namespace {

QByteArray headerValue(const HttpResponse &response, const QByteArray &wanted, bool *found = nullptr)
{
    if (found)
        *found = false;
    for (const HttpResponse::HeaderRange &range : response.field120) {
        const QByteArray name = response.raw.mid(range.name.offset, range.name.length);
        if (name.compare(wanted, Qt::CaseInsensitive) != 0)
            continue;
        if (found)
            *found = true;
        return response.raw.mid(range.value.offset, range.value.length);
    }
    return {};
}

bool nativeResponseIsEligible(const HttpResponse &response)
{
    // gui.exe:0x14007D6A0, called first by 0x14007D700.
    const qint32 state = static_cast<qint32>(response.error);
    if (((state - 1) & 0xfa) == 0 && state != 2)
        return false;
    const int requestKind = response.request.attribute(
        static_cast<QNetworkRequest::Attribute>(1012)).toInt();
    return (requestKind == 1 || requestKind == 2)
        && response.statusCode > 0
        && (response.statusCode < 400 || response.statusCode > 499)
        && !response.field170;
}

bool isHtml(const HttpResponse &response)
{
    return headerValue(response, QByteArrayLiteral("Content-Type"))
        .trimmed().toLower().startsWith(QByteArrayLiteral("text/html"));
}

QString metaCacheControl(const HttpResponse &response)
{
    // gui.exe:0x1401376F0 with tag=meta, key=http-equiv,
    // key-value=Cache-Control, then attribute=content.
    const QString body = QString::fromUtf8(response.raw.mid(response.bodyOffset,
                                                             response.bodyLength));
    const QRegularExpression tag(
        QStringLiteral("<") + QRegularExpression::escape(QStringLiteral("meta"))
            + QStringLiteral("\\s+[^>]*?\\b")
            + QRegularExpression::escape(QStringLiteral("http-equiv"))
            + QStringLiteral("\\s*=\\s*['\"]?")
            + QRegularExpression::escape(QStringLiteral("Cache-Control"))
            + QStringLiteral("['\"]?[^>]*?>"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch tagMatch = tag.match(body);
    if (!tagMatch.hasMatch())
        return {};
    const QRegularExpression content(
        QRegularExpression::escape(QStringLiteral("content"))
            + QStringLiteral("\\s*=\\s*(?(?=[\"'])(['\"])([\\s\\S]*?)\\1|([^\\s>]+))"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch contentMatch = content.match(tagMatch.captured(0));
    if (!contentMatch.hasMatch())
        return {};
    const QString quoted = contentMatch.captured(2);
    return quoted.isNull() ? contentMatch.captured(3) : quoted;
}

bool isDynamicPath(const QUrl &url)
{
    // gui.exe:0x14014F510 / 0x14014F950.
    const QString fileName = url.fileName(QUrl::FullyDecoded);
    const qsizetype dot = fileName.lastIndexOf(QLatin1Char('.'));
    if (dot < 0 || dot + 1 == fileName.size())
        return !fileName.isEmpty();
    static const QRegularExpression dynamicExtension(
        QStringLiteral("^(asp|aspx|axd|asx|asmx|ashx|cfm|yaws|jsp|jspx|wss|do|action|pl|php|php4|php3|phtml|py|rb|rhtml|shtml|cgi|dll)$"),
        QRegularExpression::CaseInsensitiveOption);
    return dynamicExtension.matchView(QStringView(fileName).sliced(dot + 1)).hasMatch();
}

} // namespace

std::optional<CacheControlFinding> evaluateCacheControlRule(
    const HttpResponse &response, int sharedClassifierResult)
{
    // gui.exe:0x14007D700. The initial condition is the shared classifier's
    // non-zero return, followed by the native HTML/response guards.
    if (!nativeResponseIsEligible(response) || !isHtml(response)
        || sharedClassifierResult == 0 || response.url.path(QUrl::FullyDecoded).size() > 100
        || !isDynamicPath(response.url)) {
        return std::nullopt;
    }

    bool hasHeader = false;
    QByteArray value = headerValue(response, QByteArrayLiteral("Cache-Control"), &hasHeader)
                           .toLower();
    if (value.isEmpty())
        value = metaCacheControl(response).toUtf8();

    const bool hasNoCache = value.contains(QByteArrayLiteral("no-cache"));
    const bool hasNoStore = value.contains(QByteArrayLiteral("no-store"));
    const bool hasPrivate = value.contains(QByteArrayLiteral("private"));
    const bool hasMaxAgeZero = value.contains(QByteArrayLiteral("max-age=0"));
    const bool hasMustRevalidate = value.contains(QByteArrayLiteral("must-revalidate"));
    if (hasNoCache || hasNoStore || hasPrivate || (hasMaxAgeZero && hasMustRevalidate))
        return std::nullopt;

    CacheControlFinding finding;
    finding.value = value;
    finding.identitySuffix = QString::fromUtf8(QByteArrayLiteral("bad-cache-control@") + value);
    if (!hasHeader) {
        finding.details = QStringLiteral("The `Cache-Control` header is not set");
        return finding;
    }

    QStringList absent{
        QStringLiteral("`no-store`"),
        QStringLiteral("`no-cache`"),
        QStringLiteral("`private`"),
        hasMaxAgeZero ? QStringLiteral("`must-revalidate`")
                      : QStringLiteral("`max-age=0, must-revalidate`"),
    };
    finding.details = QStringLiteral("The `Cache-Control` header does not have any of (%1) directives")
                          .arg(absent.join(QLatin1Char(',')));
    return finding;
}
