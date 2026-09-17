#include "filecountconstrain.h"

#include "urlnormalizer.h"

#include <QStringView>

FileCountConstrain::FileCountConstrain() = default;

QUrl FileCountConstrain::normalizeForConstraint(const QUrl &url, quint8 flags)
{
    // gui.exe:0x140160870 / 0x140160630: canonicalize, then reparse with
    // QUrl::fromUserInput and the default resolution options.
    return QUrl::fromUserInput(UrlNormalizer::canonical(url, flags));
}

qsizetype FileCountConstrain::pathDepth(const QUrl &url)
{
    // gui.exe:0x14014F450
    QString path = url.adjusted(QUrl::NormalizePathSegments).path();
    if (path == QStringLiteral("/"))
        path.clear();
    return path.count(u'/', Qt::CaseSensitive);
}

QString FileCountConstrain::directoryUrl(const QUrl &url, qsizetype depth)
{
    // gui.exe:0x140150310
    const QString path = url.adjusted(QUrl::NormalizePathSegments).path();
    const qsizetype end = qMax<qsizetype>(depth - 1, 0);
    QString directory = path.section(u'/', 0, end, QString::SectionIncludeTrailingSep);

    QUrl prefix(url);
    prefix.setPath(directory, QUrl::DecodedMode);
    QString result = prefix.toString(QUrl::RemoveFilename | QUrl::NormalizePathSegments
                                     | QUrl::StripTrailingSlash | QUrl::RemoveQuery
                                     | QUrl::RemoveFragment);
    if (!result.endsWith(u'/', Qt::CaseSensitive))
        result.append(u'/');
    return result;
}

QString FileCountConstrain::pathComponent(const QUrl &url, qsizetype depth)
{
    // gui.exe:0x140150250
    const QStringList parts = url.adjusted(QUrl::NormalizePathSegments).path()
                                  .split(u'/', Qt::KeepEmptyParts, Qt::CaseSensitive);
    if (depth <= 0 || depth >= parts.size())
        return {};
    return parts.at(depth);
}

bool FileCountConstrain::acceptAndRecord(const QUrl &input)
{
    // gui.exe:0x140160870
    const QUrl url = normalizeForConstraint(input, 46);
    const qsizetype depthCount = pathDepth(url);

    for (qsizetype depth = 1; depth <= depthCount; ++depth) {
        quint32 limit = depth < field0C ? field08 : field10;
        const auto configuredLimit = field18.constFind(quint32(depth));
        if (configuredLimit != field18.cend())
            limit = configuredLimit.value();

        const quint64 directoryHash = qHash(QStringView(directoryUrl(url, depth)), 0);
        const quint64 componentHash = qHash(QStringView(pathComponent(url, depth)), 0);
        QSet<quint64> &components = field20[directoryHash];

        // The native first checks for an existing component. A duplicate is
        // accepted even if the existing directory has already reached limit.
        if (!components.contains(componentHash)) {
            if (quint64(components.size()) >= limit)
                return false;
            components.insert(componentHash);
        }
    }
    return true;
}

bool FileCountConstrain::contains(const QUrl &input) const
{
    // gui.exe:0x140160630
    const QUrl url = normalizeForConstraint(input, 14);
    const qsizetype depth = pathDepth(url);
    const quint64 directoryHash = qHash(QStringView(directoryUrl(url, depth)), 0);
    const auto directory = field20.constFind(directoryHash);
    if (directory == field20.cend())
        return false;

    const QString component = pathComponent(url, depth);
    if (component.isEmpty())
        return true;
    return directory->contains(qHash(QStringView(component), 0));
}
