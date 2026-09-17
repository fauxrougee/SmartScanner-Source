#include "custom404urlscope.h"

namespace {

constexpr QUrl::ComponentFormattingOptions pathCountFormatting =
    static_cast<QUrl::ComponentFormattingOptions>(4096);
constexpr QUrl::ComponentFormattingOptions pathRootFormatting =
    static_cast<QUrl::ComponentFormattingOptions>(6144);
constexpr QUrl::ComponentFormattingOptions fileNameFormatting =
    static_cast<QUrl::ComponentFormattingOptions>(133169152);
constexpr QUrl::ComponentFormattingOptions rootUrlFormatting =
    static_cast<QUrl::ComponentFormattingOptions>(7360);
constexpr QUrl::ComponentFormattingOptions parentKeyFormatting =
    static_cast<QUrl::ComponentFormattingOptions>(64);

} // namespace

int custom404PathSlashCount(const QUrl &url)
{
    // gui.exe:0x14014F450.
    QString path = url.path(pathCountFormatting);
    if (path.compare(QStringLiteral("/"), Qt::CaseSensitive) == 0)
        path.clear();
    return path.count(QLatin1Char('/'), Qt::CaseSensitive);
}

QString custom404PathRoot(const QUrl &url, int depth)
{
    // gui.exe:0x140150310. The source count is converted to max(depth-1, 0)
    // before QString::section using SectionSkipEmpty (flag 4).
    const QString path = url.path(pathRootFormatting);
    const QString section = path.section(QLatin1Char('/'), 0, qMax(depth - 1, 0),
                                         QString::SectionSkipEmpty);
    QUrl normalized(url);
    // gui.exe passes QUrl::ParsingMode value 2 (DecodedMode), not the
    // default TolerantMode.
    normalized.setPath(section, QUrl::DecodedMode);
    QString result = normalized.toString(rootUrlFormatting);
    if (!result.endsWith(QLatin1Char('/'), Qt::CaseSensitive))
        result += QLatin1Char('/');
    return result;
}

bool custom404SamePathRoot(const QUrl &first, const QUrl &second,
                           bool directoryAdjustment)
{
    // gui.exe:0x14014F650.
    int firstDepth = custom404PathSlashCount(first);
    if (directoryAdjustment && first.fileName(fileNameFormatting).isEmpty())
        --firstDepth;
    int secondDepth = custom404PathSlashCount(second);
    if (directoryAdjustment && second.fileName(fileNameFormatting).isEmpty())
        --secondDepth;
    return custom404PathRoot(first, firstDepth) == custom404PathRoot(second, secondDepth);
}

QString custom404ParentDirectoryKey(const QUrl &url)
{
    // gui.exe:0x140150840.
    const QString serialized = url.toString(parentKeyFormatting);
    return serialized.left(serialized.lastIndexOf(QLatin1Char('/'), -1,
                                                  Qt::CaseSensitive))
        + QLatin1Char('/');
}
