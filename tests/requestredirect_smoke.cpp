#include "requestredirect.h"

#include <QCoreApplication>

namespace {

constexpr QNetworkRequest::Attribute nativeAttribute(int value)
{
    return static_cast<QNetworkRequest::Attribute>(value);
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    QNetworkRequest request(QUrl(QStringLiteral("https://example.test/a/page")));
    request.setAttribute(nativeAttribute(1011), 0x20);
    request.setAttribute(nativeAttribute(1003), QByteArrayLiteral("body"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("text/plain"));
    request.setHeader(QNetworkRequest::ContentLengthHeader, 4);
    request.setHeader(QNetworkRequest::UserAgentHeader, QByteArrayLiteral("native-agent"));
    request.setRawHeader("Cookie", "a=b");

    const QUrl replyUrl(QStringLiteral("https://example.test/a/page"));
    if (prepareRequestRedirect(true, request, replyUrl, QVariant(), 5).result
        != RequestRedirectPreparationResult::MissingRedirectionTarget)
        return 1;
    if (prepareRequestRedirect(false, request, replyUrl, QUrl(QStringLiteral("next")), 5).result
        != RequestRedirectPreparationResult::NoReplyOrNotEnabled)
        return 2;

    QNetworkRequest disabled(request);
    disabled.setAttribute(nativeAttribute(1011), 0);
    if (prepareRequestRedirect(true, disabled, replyUrl, QUrl(QStringLiteral("next")), 5).result
        != RequestRedirectPreparationResult::NoReplyOrNotEnabled)
        return 3;

    QNetworkRequest exhausted(request);
    exhausted.setAttribute(nativeAttribute(1008), 5);
    if (prepareRequestRedirect(true, exhausted, replyUrl, QUrl(QStringLiteral("next")), 5).result
        != RequestRedirectPreparationResult::RetryLimitReached)
        return 4;

    const RequestRedirectPreparation prepared = prepareRequestRedirect(
        true, request, replyUrl, QUrl(QStringLiteral("next?x=1")), 5);
    if (!prepared.isPrepared()
        || prepared.request.url() != QUrl(QStringLiteral("https://example.test/a/next?x=1"))
        || prepared.request.attribute(nativeAttribute(1007)).toUrl() != replyUrl
        || prepared.request.attribute(nativeAttribute(1008)).toInt() != 1
        || prepared.request.attribute(nativeAttribute(1003)).isValid()
        || prepared.request.header(QNetworkRequest::ContentTypeHeader).isValid()
        || prepared.request.header(QNetworkRequest::ContentLengthHeader).isValid()
        || prepared.request.header(QNetworkRequest::UserAgentHeader).toByteArray()
               != QByteArrayLiteral("native-agent")
        || prepared.request.header(QNetworkRequest::CookieHeader).isValid()
        || prepared.request.attribute(QNetworkRequest::CustomVerbAttribute).metaType().id()
               != QMetaType::QString
        || prepared.request.attribute(QNetworkRequest::CustomVerbAttribute).toByteArray()
               != QByteArrayLiteral("G"))
        return 5;

    QNetworkRequest laterAttempt(request);
    laterAttempt.setAttribute(nativeAttribute(1008), 2);
    const RequestRedirectPreparation later = prepareRequestRedirect(
        true, laterAttempt, replyUrl, QUrl(QStringLiteral("/elsewhere")), 5);
    return later.isPrepared()
               && !later.request.attribute(nativeAttribute(1007)).isValid()
               && later.request.attribute(nativeAttribute(1008)).toInt() == 3
           ? 0
           : 6;
}
