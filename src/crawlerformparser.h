#pragma once

#include "httprequestrawpacket.h"

#include <QList>
#include <QUrl>

// Deterministic document-to-HtmlForm slice of gui.exe:0x1400EEF70.  Native
// FileList insertion and the form-value-rule ownership are separate paths;
// this returns only the directly constructed HtmlForm objects.
[[nodiscard]] QList<HtmlForm> crawlerHtmlForms(const QUrl &responseUrl,
                                                const QString &document);
