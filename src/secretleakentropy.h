#pragma once

#include <QString>
#include <QRegularExpression>

// Reconstruction label for gui.exe:0x140054CF0.  The native routine counts
// UTF-16 QChar units and returns zero for a null or empty QString.
[[nodiscard]] double secretLeakTextEntropy(const QString &text);

// Reconstruction label for gui.exe:0x140045A40.  It returns the line slice
// around an UTF-16 offset; an out-of-range offset returns a default QString.
[[nodiscard]] QString secretLeakContextLine(const QString &text, int offset);

// Reconstruction label for gui.exe:0x140054EF0.  The native recognizes a
// case-insensitive leading `(?i)` marker without trimming the rule string.
[[nodiscard]] QRegularExpression secretLeakCompilePattern(const QString &rule);
