#ifndef XXEDETECTOR_H
#define XXEDETECTOR_H

#include <QString>
#include <QStringList>

class XxeDetector
{
public:
    enum class XxeType {
        None,
        ClassicXxe,
        BlindXxe,
        ErrorBasedXxe,
        ParameterEntityXxe,
        OobXxe
    };
    XxeDetector() = default;
    ~XxeDetector() = default;

    XxeType detect(const QString &responseBody, const QString &expectedContent) const;
    bool isVulnerable(const QString &responseBody) const;

    static QStringList getPayloads();
    static QStringList getOobPayloads(const QString &collaboratorDomain);
    static int severityLevel(XxeType type);
};

#endif // XXEDETECTOR_H
