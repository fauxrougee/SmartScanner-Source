#include "secretleakmatchrecord.h"

SecretLeakMatchRecord secretLeakGlobalMatchRecord(
    const QString &field0, const QString &field24, const QString &rawCapture,
    const QString &selectedCapture, qint32 capturedStart, double score)
{
    // gui.exe:0x140054b51-0x140054c04. Four QString copies are followed by
    // capturedStart at +96 and the entropy score at +104.
    return {field0, field24, rawCapture, selectedCapture, capturedStart, score};
}

SecretLeakMatchRecord secretLeakPathMatchRecord(
    const QString &field0, const QString &field24)
{
    // gui.exe:0x14005469a-0x14005474a. The hasMatch branch writes the first
    // two QString fields and zero-initializes both capture strings, start and
    // score before appending its one record.
    return {field0, field24, {}, {}, 0, 0.0};
}
