#pragma once

#include <QHash>
#include <QStringList>

class HttpResponse;

// gui.exe:0x14014DEF0 non-401/non-4xx/non-5xx tail. The retained-body match,
// directory cache and stored scopes are externally-owned detector state.
[[nodiscard]] int custom404ClassifyNonExceptionalResponse(
    const HttpResponse &response, bool matchesRetainedBody,
    const QHash<quint64, QByteArray> &directoryBodies,
    const QStringList &storedScopes);
