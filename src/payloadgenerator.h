#ifndef PAYLOADGENERATOR_H
#define PAYLOADGENERATOR_H

#include <QString>
#include <QStringList>
#include <QHash>
#include <QByteArray>
#include <QUrl>

class PayloadGenerator {
public:
    static QStringList generateSqlTimeBasedPayloads();
    static QStringList generateSqlErrorBasedPayloads();
    static QStringList generateSqlUnionPayloads(int columns);
    static QStringList generateSqlBooleanPayloads();
    static QStringList generateSqlStackedPayloads();

    static QStringList generateXssReflectedPayloads();
    static QStringList generateXssStoredPayloads();
    static QStringList generateXssDomPayloads();
    static QStringList generateXssPolyglotPayloads();

    static QStringList generateSstiPayloads(const QString &engine);
    static QStringList generateSstiJinja2Payloads();
    static QStringList generateSstiTwigPayloads();
    static QStringList generateSstiFreemarkerPayloads();
    static QStringList generateSstiVelocityPayloads();
    static QStringList generateSstiMakoPayloads();

    static QStringList generateOsCommandPayloads(const QString &os);
    static QStringList generateLinuxCommandPayloads();
    static QStringList generateWindowsCommandPayloads();

    static QStringList generateLfiPayloads();
    static QStringList generateRfiPayloads();
    static QStringList generatePathNormalizationPayloads();

    static QStringList generateXxeOobPayloads(const QString &callback);
    static QStringList generateXxeErrorPayloads();
    static QStringList generateXxeLocalPayloads();

    static QStringList generateSsrfIpBypassPayloads();
    static QStringList generateSsrfProtocolPayloads();
    static QStringList generateSsrfCloudMetadataPayloads();

    static QStringList generateLdapPayloads();
    static QStringList generateXpathPayloads();
    static QStringList generateNoSqlPayloads();
    static QStringList generateGraphqlPayloads();

    static QStringList generateJwtPayloads(const QString &header, const QString &payload);
    static QStringList generateCsrfPayloads(const QString &action);
    static QStringList generateCorsPayloads();

    static QString obfuscatePayload(const QString &payload, const QString &technique);
    static QStringList generateWafBypassVariants(const QString &payload);
    static QString applyEncoding(const QString &payload, const QString &encoding);
    static QStringList getAllEncodings();
};

#endif // PAYLOADGENERATOR_H
