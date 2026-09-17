#pragma once

#include <QString>
#include <QUrl>

// gui.exe:0x140150490, after its separate native HTML-entity decoder. The
// caller must supply the already-decoded location capture from sitemap data.
[[nodiscard]] QUrl resolveDecodedSitemapLocation(const QUrl &base,
                                                  QString decodedLocation);

// gui.exe:0x140150490 complete public path: entity decode, trim, cleanup and
// QUrl::resolved.  The decoded-only form above remains for its internal slice.
[[nodiscard]] QUrl resolveSitemapLocation(const QUrl &base, QString location);
