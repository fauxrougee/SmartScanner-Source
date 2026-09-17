#pragma once

#include <QByteArray>
#include <QUrl>

// gui.exe:0x14014E3D0 / 0x140137B00. Produces the retained Custom404 body
// form after URL-derived text has been removed.
[[nodiscard]] QByteArray custom404MaskedBody(const QByteArray &body, const QUrl &url);
