#pragma once

#include <QByteArray>
#include <QString>

#include <optional>

class HttpResponse;

// Stateless result of gui.exe:0x14007D700 after the shared response
// classifier has completed. The classifier result is deliberately explicit:
// its Custom404Detector state has not yet been reconstructed.
struct CacheControlFinding final {
    QByteArray value;
    QString details;
    QString identitySuffix;
};

[[nodiscard]] std::optional<CacheControlFinding> evaluateCacheControlRule(
    const HttpResponse &response, int sharedClassifierResult);
