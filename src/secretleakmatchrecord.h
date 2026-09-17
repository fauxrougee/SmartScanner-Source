#pragma once

#include <QtGlobal>

#include <QString>

// Source-reconstruction representation of one observed 112-byte matcher
// output record from gui.exe:0x140054490. Field labels are positional because
// the original member names were not preserved.
struct SecretLeakMatchRecord {
    QString field0;
    QString field24;
    QString rawCapture;
    QString selectedCapture;
    qint32 capturedStart = 0;
    double score = 0.0;
};

[[nodiscard]] SecretLeakMatchRecord secretLeakGlobalMatchRecord(
    const QString &field0, const QString &field24, const QString &rawCapture,
    const QString &selectedCapture, qint32 capturedStart, double score);

[[nodiscard]] SecretLeakMatchRecord secretLeakPathMatchRecord(
    const QString &field0, const QString &field24);
