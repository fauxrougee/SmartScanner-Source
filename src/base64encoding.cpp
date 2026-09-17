#include "base64encoding.h"

// gui.exe:0x1400AE280 toBase64(input, options=0).
QByteArray Base64Encoding::transform(const QByteArray &input)
{
    return input.toBase64();
}

// gui.exe:0x1400AE200 fromBase64(input, options=0).
QByteArray Base64Encoding::decode(const QByteArray &input)
{
    return QByteArray::fromBase64(input);
}
