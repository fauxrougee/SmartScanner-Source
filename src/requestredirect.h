#pragma once

#include <QNetworkRequest>
#include <QUrl>
#include <QVariant>

// Deterministic preparation half of sms.exe:0x140135CA0. The native routine
// submits the prepared request through RequestManager immediately afterwards;
// that queue/cookie state is intentionally not represented by this value type.
enum class RequestRedirectPreparationResult {
    Prepared = 0,
    MissingRedirectionTarget = 1,
    NoReplyOrNotEnabled = 2,
    InvalidResolvedTarget = 3,
    RetryLimitReached = 4,
};

struct RequestRedirectPreparation {
    RequestRedirectPreparationResult result =
        RequestRedirectPreparationResult::MissingRedirectionTarget;
    QNetworkRequest request;

    [[nodiscard]] bool isPrepared() const noexcept
    {
        return result == RequestRedirectPreparationResult::Prepared;
    }
};

// `replyExists` preserves the native distinction between a valid redirect
// attribute on a null reply and every other rejection after the attribute
// lookup. `maximumRetries` is RequestManager's native field at +76.
[[nodiscard]] RequestRedirectPreparation prepareRequestRedirect(
    bool replyExists, const QNetworkRequest &replyRequest, const QUrl &replyUrl,
    const QVariant &redirectionTarget, int maximumRetries);
