#include "custom404bodymasker.h"

namespace {

constexpr QUrl::ComponentFormattingOptions decodedComponents =
    static_cast<QUrl::ComponentFormattingOptions>(133169152);

void maskUrlDerivedText(QString &text, const QUrl &url)
{
    // gui.exe:0x140137B00. QString::replace receives CaseSensitivity value 0.
    const QString serialized = url.toString();
    for (int length = serialized.size(); length > 6; --length) {
        const QString before = text;
        text.replace(serialized.left(length), QString(), Qt::CaseInsensitive);
        if (text == before)
            break;
    }

    const QString host = url.host(decodedComponents);
    for (int length = host.size(); length > 5; --length) {
        const QString before = text;
        text.replace(host.right(length), QString(), Qt::CaseInsensitive);
        if (text != before)
            break;
    }

    const QString path = url.path(decodedComponents);
    if (path.size() > 5)
        text.replace(path, QString(), Qt::CaseInsensitive);
}

} // namespace

QByteArray custom404MaskedBody(const QByteArray &body, const QUrl &url)
{
    // gui.exe:0x14014E3D0 obtains the native response body, constructs a
    // QString from its QByteArray, invokes the masker, then returns UTF-8.
    if (body.isEmpty())
        return {};
    QString text = QString::fromUtf8(body);
    maskUrlDerivedText(text, url);
    return text.toUtf8();
}
