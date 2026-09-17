#pragma once

#include <QRegularExpressionMatch>

struct SecretLeakCaptureSelection {
    QString rawCapture;
    QString selectedCapture;
    qint32 capturedStart = 0;
};

// Reconstruction label for gui.exe:0x1400549BA-0x140054AB6.  The boolean and
// index are source labels for the two observed native rule fields.
[[nodiscard]] SecretLeakCaptureSelection secretLeakSelectCapture(
    const QRegularExpressionMatch &match, bool useExplicitCaptureIndex,
    qint32 explicitCaptureIndex);
