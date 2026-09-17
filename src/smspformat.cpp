#include "smspformat.h"

#include <QByteArray>
#include <QString>

namespace {

constexpr quint32 smspVersion = 300;
const QByteArray smspMagic("SmartScanner");
const QString smspEdition = QStringLiteral("Pro");
const QString smspTerminalMarker = QStringLiteral("eof");

} // namespace

void writeSmspPreamble(QDataStream &stream)
{
    // gui.exe:0x1400E2910
    stream << smspMagic << smspVersion << smspEdition;
}

void writeSmspTerminalMarker(QDataStream &stream)
{
    // gui.exe:0x1400E2910
    stream << smspTerminalMarker;
}

SmspEnvelopeStatus readSmspPreamble(QDataStream &stream)
{
    // gui.exe:0x1400E1CA0. The edition field is read but not validated.
    QByteArray magic;
    quint32 version = 0;
    QString ignoredEdition;
    stream >> magic;
    if (stream.status() != QDataStream::Ok)
        return SmspEnvelopeStatus::CorruptedData;
    if (magic != smspMagic)
        return SmspEnvelopeStatus::InvalidFile;
    stream >> version;
    if (stream.status() != QDataStream::Ok)
        return SmspEnvelopeStatus::CorruptedData;
    // gui.exe:0x1400E1D30 rejects an older on-disk layout as corrupted;
    // 0x1400E1D36 distinguishes a future layout as unsupported.
    if (version < smspVersion)
        return SmspEnvelopeStatus::CorruptedData;
    if (version > smspVersion)
        return SmspEnvelopeStatus::UnsupportedVersion;
    stream >> ignoredEdition;
    return stream.status() == QDataStream::Ok ? SmspEnvelopeStatus::Ok
                                               : SmspEnvelopeStatus::CorruptedData;
}

SmspEnvelopeStatus readSmspTerminalMarker(QDataStream &stream)
{
    // gui.exe:0x1400E1CA0
    QString marker;
    stream >> marker;
    if (stream.status() != QDataStream::Ok)
        return SmspEnvelopeStatus::CorruptedData;
    return marker == smspTerminalMarker ? SmspEnvelopeStatus::Ok
                                        : SmspEnvelopeStatus::InvalidFile;
}
