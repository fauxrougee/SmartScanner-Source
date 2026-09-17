#include "dircountconstrain.h"

#include <QStringView>

DirCountConstrain::DirCountConstrain() = default;

bool DirCountConstrain::acceptAndRecord(const QUrl &input)
{
    // gui.exe:0x140160BE0
    QUrl url = normalizeForConstraint(input, 46);
    const bool hasFileName = !url.fileName(QUrl::FullyDecoded).isEmpty();
    url = QUrl(directoryUrl(url, pathDepth(url)));

    const quint64 urlHash = qHash(url, 0);
    if (field28.contains(urlHash))
        return false;
    field28.insert(urlHash);

    const qsizetype depthCount = pathDepth(url);
    for (qsizetype depth = 0; depth <= depthCount; ++depth) {
        quint32 limit = depth < field0C ? field08 : field10;
        const auto configuredLimit = field18.constFind(quint32(depth));
        if (configuredLimit != field18.cend())
            limit = configuredLimit.value();

        const quint64 componentHash = qHash(QStringView(pathComponent(url, depth)), 0);
        const quint64 directoryHash = qHash(QStringView(directoryUrl(url, depth)), 0);
        QSet<quint64> &components = field20[directoryHash];

        if (components.contains(componentHash)) {
            // The native only rejects this existing component at the last
            // level when the original URL had a filename (or was root).
            if (depth == depthCount && (hasFileName || depthCount == 0))
                return false;
            continue;
        }

        if (quint64(components.size()) < limit) {
            components.insert(componentHash);
            continue;
        }

        const qint32 previous = field30;
        --field30;
        return previous > 0;
    }
    return true;
}
