#ifndef FUZZENGINE_H
#define FUZZENGINE_H

#include <QString>
#include <QStringList>
#include <QList>
#include <QHash>
#include <QByteArray>
#include <QUrl>

class FuzzEngine {
public:
    static QStringList getSqlInjectionPayloads();
    static QStringList getXssPayloads();
    static QStringList getPathTraversalPayloads();
    static QStringList getCommandInjectionPayloads();
    static QStringList getLdapInjectionPayloads();
    static QStringList getXpathInjectionPayloads();
    static QStringList getSstiPayloads();
    static QStringList getXxePayloads();
    static QStringList getCsrfPayloads();
    static QStringList getOpenRedirectPayloads();
    static QStringList getHostHeaderPayloads();
    static QStringList getCrlfjectionPayloads();
    static QStringList getNoSqlInjectionPayloads();
    static QStringList getSsrfPayloads();

    static QStringList getUserAgents();
    static QStringList getCommonPasswords();
    static QStringList getCommonUsernames();
    static QStringList getFileExtensions();
    static QStringList getBackupExtensions();
    static QStringList getConfigFiles();
    static QStringList getSensitiveFiles();

    static QString encodePayload(const QString &payload, const QString &encoding);
    static QString doubleEncode(const QString &payload);
    static QString unicodeEncode(const QString &payload);
    static QString hexEncode(const QString &payload);
    static QString base64Encode(const QString &payload);
    static QString urlEncode(const QString &payload);

    static QStringList mutatePayload(const QString &payload);
    static QStringList generateFuzzStrings(int count);
    static QByteArray generateRandomBytes(int length);
};

#endif // FUZZENGINE_H
