#include "secretleakcapture.h"

SecretLeakCaptureSelection secretLeakSelectCapture(
    const QRegularExpressionMatch &match, bool useExplicitCaptureIndex,
    qint32 explicitCaptureIndex)
{
    // gui.exe:0x1400549BA-0x140054AB6. Begin with captured(0) and its trimmed
    // copy. If a group is selected, native code assigns it directly (without
    // trimming); otherwise it uses the first non-empty group when one exists.
    SecretLeakCaptureSelection selection;
    selection.rawCapture = match.captured(0);
    selection.selectedCapture = selection.rawCapture.trimmed();
    selection.capturedStart = static_cast<qint32>(match.capturedStart(0));

    const qint32 last = static_cast<qint32>(match.lastCapturedIndex());
    if (last < 1)
        return selection;

    if (useExplicitCaptureIndex && explicitCaptureIndex > 0
        && explicitCaptureIndex <= last) {
        selection.selectedCapture = match.captured(explicitCaptureIndex);
        return selection;
    }

    for (qint32 index = 1; index <= last; ++index) {
        const QString capture = match.captured(index);
        if (!capture.isEmpty()) {
            selection.selectedCapture = capture;
            break;
        }
    }
    return selection;
}
