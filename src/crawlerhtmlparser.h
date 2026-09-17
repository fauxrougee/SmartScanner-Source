#pragma once

#include <QList>
#include <QRegularExpression>
#include <QUrl>

// gui.exe:0x14006C690. The expressions are all constructed with pattern
// option 1 (CaseInsensitiveOption).
[[nodiscard]] const QRegularExpression &crawlerHrefExpression();
[[nodiscard]] const QRegularExpression &crawlerSourceExpression();
[[nodiscard]] const QRegularExpression &crawlerIframeExpression();
[[nodiscard]] const QRegularExpression &crawlerScriptExpression();
[[nodiscard]] const QRegularExpression &crawlerMetaRefreshExpression();

// gui.exe:0x14006E3D4-0x14006E5D4. An absent Content-Type is accepted; a
// present value is accepted only when it starts with `text` and does not
// contain `javascript`. QByteArray nullness deliberately distinguishes a
// missing header from a present empty value.
[[nodiscard]] bool crawlerAcceptsContentType(const QByteArray &contentType);

// gui.exe:0x1400718F0. These helpers model only the candidate extraction and
// URL resolution prior to FileList insertion. They intentionally perform no
// request scheduling.
[[nodiscard]] QList<QUrl> crawlerHtmlHrefLocations(const QUrl &requestUrl,
                                                    const QString &document);
[[nodiscard]] QList<QUrl> crawlerHtmlIframeLocations(const QUrl &requestUrl,
                                                      const QString &document);
[[nodiscard]] QList<QUrl> crawlerHtmlSourceLocations(const QUrl &requestUrl,
                                                      const QString &document);

// gui.exe:0x140071A28 through 0x140071B08. QRegularExpression::match is used,
// so the returned list contains zero or one location and does not apply the
// normal link-rejection predicate.
[[nodiscard]] QList<QUrl> crawlerMetaRefreshLocations(const QUrl &requestUrl,
                                                       const QString &document);
