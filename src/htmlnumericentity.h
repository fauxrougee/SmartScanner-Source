#pragma once

#include <QString>

// gui.exe:0x140159760 outer entity decoder, with the directly recovered
// amp/gt/lt/apos subset from gui.exe:0x1401514D0.
[[nodiscard]] QString decodeHtmlCharacterReferences(QString input);

// Numeric branch only, retained for callers that need its narrower contract.
[[nodiscard]] QString decodeNumericHtmlCharacterReferences(QString input);
