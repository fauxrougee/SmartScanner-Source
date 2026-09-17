#include "requestredirect.h"

namespace {

constexpr QNetworkRequest::Attribute nativeAttribute(int value)
{
    return static_cast<QNetworkRequest::Attribute>(value);
}

} // namespace

RequestRedirectPreparation prepareRequestRedirect(
    bool replyExists, const QNetworkRequest &replyRequest, const QUrl &replyUrl,
    const QVariant &redirectionTarget, int maximumRetries)
{
    // sms.exe:0x140135CA0. QNetworkReply::attribute(2) is checked before the
    // reply pointer and before the request's opt-in bit.
    if (!redirectionTarget.isValid())
        return {RequestRedirectPreparationResult::MissingRedirectionTarget, {}};

    if (!replyExists
        || (replyRequest.attribute(nativeAttribute(1011)).toInt() & 0x20) == 0) {
        return {RequestRedirectPreparationResult::NoReplyOrNotEnabled, {}};
    }

    const QUrl target = replyUrl.resolved(redirectionTarget.toUrl());
    if (!target.isValid())
        return {RequestRedirectPreparationResult::InvalidResolvedTarget, {}};

    int retryCount = replyRequest.attribute(nativeAttribute(1008), -1).toInt();
    if (retryCount >= maximumRetries)
        return {RequestRedirectPreparationResult::RetryLimitReached, {}};

    QNetworkRequest request(replyRequest);
    if (retryCount == -1) {
        request.setAttribute(nativeAttribute(1007), replyUrl);
        retryCount = 0;
    }
    request.setAttribute(nativeAttribute(1008), retryCount + 1);
    request.setUrl(target);
    request.setAttribute(nativeAttribute(1003), QVariant());
    request.setHeader(QNetworkRequest::ContentTypeHeader, QVariant());
    request.setHeader(QNetworkRequest::ContentLengthHeader, QVariant());
    // sms.exe:0x140135F5A / 0x140135F96: QVariant(const char*) and header 4.
    request.setAttribute(QNetworkRequest::CustomVerbAttribute, QStringLiteral("G"));
    request.setHeader(QNetworkRequest::CookieHeader, QVariant());
    return {RequestRedirectPreparationResult::Prepared, request};
}
