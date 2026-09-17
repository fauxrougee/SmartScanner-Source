#ifndef LFIDETECTOR_H
#define LFIDETECTOR_H

#include <QString>
#include <QStringList>

class LfiDetector
{
public:
    enum class LfiType {
        None,
        BasicLfi,
        NullByteInjection,
        DoubleEncoding,
        PathTruncation,
        FilterBypass,
        WrapperBased
    };
    enum class OsTarget {
        Linux,
        Windows,
        Both
    };
    LfiDetector() = default;
    ~LfiDetector() = default;

    LfiType detect(const QString &responseBody) const;
    bool isVulnerable(const QString &responseBody) const;

    static QStringList getPayloads(OsTarget os);
    static QStringList getPhpWrapperPayloads();
    static QStringList getInterestingFiles(OsTarget os);
    static int severityLevel(LfiType type);
};

#endif // LFIDETECTOR_H
