#ifndef SSRFDETECTOR_H
#define SSRFDETECTOR_H

#include <QString>
#include <QStringList>
#include <QUrl>
#include <QHostAddress>

class SsrfDetector
{
public:
    enum class SsrfType {
        None,
        BasicSsrf,
        BlindSsrf,
        PartialSsrf,
        ProtocolSmuggling
    };
    SsrfDetector() = default;
    ~SsrfDetector() = default;

    SsrfType detect(const QString &responseBody, const QString &expectedContent) const;
    bool isVulnerable(const QString &responseBody) const;
    bool isInternalIp(const QString &ip) const;
    bool isInternalHostname(const QString &hostname) const;

    static QStringList getPayloads();
    static QStringList getCloudMetadataEndpoints();
    static QStringList getInternalIpRanges();
    static QStringList getBypassTechniques(const QString &blockedUrl);
    static int severityLevel(SsrfType type);
};

#endif // SSRFDETECTOR_H
