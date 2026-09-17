#pragma once

#include <QByteArray>
#include <QNetworkRequest>

class HttpResponse;

// gui.exe:0x14013C520 and 0x140134350 / 0x140134390.  The output is the
// compact request/response pair attached to an Issue's native HTTP list.
[[nodiscard]] QByteArray nativeIssueRequestCapture(const QNetworkRequest &request);
[[nodiscard]] QByteArray nativeIssueResponseCapture(const HttpResponse &response);
