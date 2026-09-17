#ifndef WPVULNDETECTOR_H
#define WPVULNDETECTOR_H

#include <QString>
#include <QStringList>
#include <QMap>
#include <QUrl>
#include <QList>

class WpVulnDetector
{
public:
    enum class VulnType {
        None,
        SqlInjection,
        Xss,
        Rce,
        Lfi,
        Rfi,
        AuthBypass,
        PrivilegeEscalation,
        InformationDisclosure,
        ArbitraryFileUpload,
        Csrf
    };
    struct Vulnerability {
        QString plugin;
        QString version;
        VulnType type;
        QString cve;
        QString description;
        QString payload;
        QString endpoint;
        int severity;
    };

    WpVulnDetector() = default;
    ~WpVulnDetector() = default;

    bool isWordPress(const QString &responseBody) const;
    QString detectVersion(const QString &responseBody) const;
    QStringList detectPlugins(const QString &responseBody) const;
    QStringList detectThemes(const QString &responseBody) const;
    QList<Vulnerability> getKnownVulnerabilities(const QString &plugin, const QString &version) const;

    static QStringList getLoginPageIndicators();
    static QStringList getAdminPageIndicators();
    static QStringList getUserEnumPayloads();
    static QString typeName(VulnType type);
};

#endif // WPVULNDETECTOR_H
