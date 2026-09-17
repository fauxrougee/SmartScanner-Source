#pragma once

#include <QRegularExpression>

// gui.exe:0x1400ED730 constructs these six expressions for the form route
// invoked by CrawlerParser's response handler (gui.exe:0x1400718F0). They
// are exposed independently while native form insertion remains unrecovered.
[[nodiscard]] const QRegularExpression &crawlerFormExpression();
[[nodiscard]] const QRegularExpression &crawlerInputExpression();
[[nodiscard]] const QRegularExpression &crawlerSelectExpression();
[[nodiscard]] const QRegularExpression &crawlerTextareaExpression();
[[nodiscard]] const QRegularExpression &crawlerOptionExpression();
[[nodiscard]] const QRegularExpression &crawlerFormAttributeExpression();
