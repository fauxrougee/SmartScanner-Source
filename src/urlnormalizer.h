#pragma once

#include <QUrl>

namespace UrlNormalizer {

// Exact gui.exe:0x1401240B0 behavior. The source name describes only the
// confirmed transformation, not an unrecovered original identifier.
QUrl withoutDefaultPort(QUrl url);

// Exact gui.exe:0x1401245D0 behavior.
QUrl withoutUnqueriedRootSlash(QUrl url);

// Exact gui.exe:0x1401239B0 default-document catalogue and transformation.
QUrl withoutDefaultDocument(QUrl url);

// gui.exe:0x140124780. It sorts decoded query items by key; with
// clearValues=true, the native routine also clears every value after sorting.
QUrl withSortedQueryItems(QUrl url, bool clearValues = false);

// Exact gui.exe:0x140123500 flag-driven canonicalizer. The flag values are
// retained because original source identifiers were not recoverable.
QString canonical(const QUrl &url, quint8 flags);

// gui.exe:0x140123500 with flag value 46, used by Issue identity.
QString canonicalForIssue(const QUrl &url);

} // namespace UrlNormalizer
