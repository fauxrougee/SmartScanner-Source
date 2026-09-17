#pragma once

#include <QDataStream>

// gui.exe:0x1400E2910 / 0x1400E1CA0. This is only the verified project-file
// envelope; the unrecovered Scanner component payload belongs between its
// preamble and terminal marker.
enum class SmspEnvelopeStatus {
    Ok,
    InvalidFile,
    UnsupportedVersion,
    CorruptedData,
};

void writeSmspPreamble(QDataStream &stream);
void writeSmspTerminalMarker(QDataStream &stream);
[[nodiscard]] SmspEnvelopeStatus readSmspPreamble(QDataStream &stream);
[[nodiscard]] SmspEnvelopeStatus readSmspTerminalMarker(QDataStream &stream);
