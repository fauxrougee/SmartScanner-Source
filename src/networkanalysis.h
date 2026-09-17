#ifndef NETWORKANALYSIS_H
#define NETWORKANALYSIS_H

#include <QString>
#include <QStringList>
#include <QHash>
#include <QList>
#include <QPair>
#include <QHostAddress>
#include <QUrl>

class NetworkAnalysis {
public:
    static QStringList getCommonPorts();
    static QStringList getWebPorts();
    static QStringList getDatabasePorts();
    static QStringList getMailPorts();
    static QStringList getFileSharingPorts();

    static QString getServiceName(int port);
    static QHash<int, QString> getPortServiceMap();

    static bool isPrivateIP(const QString &ip);
    static bool isLoopbackIP(const QString &ip);
    static bool isMulticastIP(const QString &ip);
    static bool isReservedIP(const QString &ip);

    static QString getIPClass(const QString &ip);
    static QString getCIDRNotation(const QString &ip, const QString &subnet);
    static QStringList expandCIDR(const QString &cidr);

    static QStringList parseHttpHeaders(const QString &rawHeaders);
    static QHash<QString, QString> parseHeadersToMap(const QString &rawHeaders);
    static QString extractCookies(const QString &headers);
    static QStringList parseCookies(const QString &cookieString);

    static bool isValidUrl(const QString &url);
    static QString normalizeUrl(const QString &url);
    static QHash<QString, QString> parseUrlParameters(const QString &url);
    static QString buildUrl(const QString &base, const QHash<QString, QString> &params);

    static QStringList getSubdomains(const QString &domain);
    static QString extractDomain(const QString &url);
    static QString extractTLD(const QString &domain);
    static bool isValidDomain(const QString &domain);

    static QStringList detectWAF(const QString &response, const QHash<QString, QString> &headers);
    static QStringList getWAFSignatures();

    static QString detectWebServer(const QHash<QString, QString> &headers);
    static QString detectFramework(const QString &response, const QHash<QString, QString> &headers);
    static QStringList detectTechnologies(const QString &response, const QHash<QString, QString> &headers);

    static int calculateResponseTime(qint64 startMs, qint64 endMs);
    static QString categorizeResponseTime(int ms);
};

#endif // NETWORKANALYSIS_H
