#include "networkanalysis.h"
#include <QRegularExpression>

QStringList NetworkAnalysis::getCommonPorts() {
    return {
        QStringLiteral("20"),   // FTP Data
        QStringLiteral("21"),   // FTP Control
        QStringLiteral("22"),   // SSH
        QStringLiteral("23"),   // Telnet
        QStringLiteral("25"),   // SMTP
        QStringLiteral("53"),   // DNS
        QStringLiteral("67"),   // DHCP Server
        QStringLiteral("68"),   // DHCP Client
        QStringLiteral("69"),   // TFTP
        QStringLiteral("80"),   // HTTP
        QStringLiteral("110"),  // POP3
        QStringLiteral("119"),  // NNTP
        QStringLiteral("123"),  // NTP
        QStringLiteral("135"),  // MSRPC
        QStringLiteral("137"),  // NetBIOS Name
        QStringLiteral("138"),  // NetBIOS Datagram
        QStringLiteral("139"),  // NetBIOS Session
        QStringLiteral("143"),  // IMAP
        QStringLiteral("161"),  // SNMP
        QStringLiteral("162"),  // SNMP Trap
        QStringLiteral("179"),  // BGP
        QStringLiteral("389"),  // LDAP
        QStringLiteral("443"),  // HTTPS
        QStringLiteral("445"),  // SMB
        QStringLiteral("465"),  // SMTPS
        QStringLiteral("514"),  // Syslog
        QStringLiteral("515"),  // LPD
        QStringLiteral("587"),  // SMTP Submission
        QStringLiteral("636"),  // LDAPS
        QStringLiteral("993"),  // IMAPS
        QStringLiteral("995"),  // POP3S
        QStringLiteral("1080"), // SOCKS
        QStringLiteral("1433"), // MSSQL
        QStringLiteral("1434"), // MSSQL Browser
        QStringLiteral("1521"), // Oracle
        QStringLiteral("1723"), // PPTP
        QStringLiteral("2049"), // NFS
        QStringLiteral("2082"), // cPanel
        QStringLiteral("2083"), // cPanel SSL
        QStringLiteral("2086"), // WHM
        QStringLiteral("2087"), // WHM SSL
        QStringLiteral("3306"), // MySQL
        QStringLiteral("3389"), // RDP
        QStringLiteral("3690"), // SVN
        QStringLiteral("5432"), // PostgreSQL
        QStringLiteral("5900"), // VNC
        QStringLiteral("5985"), // WinRM HTTP
        QStringLiteral("5986"), // WinRM HTTPS
        QStringLiteral("6379"), // Redis
        QStringLiteral("8000"), // HTTP Alt
        QStringLiteral("8080"), // HTTP Proxy
        QStringLiteral("8443"), // HTTPS Alt
        QStringLiteral("8888"), // HTTP Alt
        QStringLiteral("9090"), // Web Console
        QStringLiteral("9200"), // Elasticsearch
        QStringLiteral("9300"), // Elasticsearch
        QStringLiteral("11211"), // Memcached
        QStringLiteral("27017"), // MongoDB
        QStringLiteral("27018"), // MongoDB
        QStringLiteral("50000"), // SAP
    };
}

QStringList NetworkAnalysis::getWebPorts() {
    return {
        QStringLiteral("80"), QStringLiteral("443"), QStringLiteral("8000"),
        QStringLiteral("8080"), QStringLiteral("8443"), QStringLiteral("8888"),
        QStringLiteral("3000"), QStringLiteral("4000"), QStringLiteral("5000"),
        QStringLiteral("9000"), QStringLiteral("9090"), QStringLiteral("9443"),
    };
}

QStringList NetworkAnalysis::getDatabasePorts() {
    return {
        QStringLiteral("1433"), QStringLiteral("1521"), QStringLiteral("3306"),
        QStringLiteral("5432"), QStringLiteral("6379"), QStringLiteral("27017"),
        QStringLiteral("9200"), QStringLiteral("11211"), QStringLiteral("5984"),
    };
}

QStringList NetworkAnalysis::getMailPorts() {
    return {
        QStringLiteral("25"), QStringLiteral("110"), QStringLiteral("143"),
        QStringLiteral("465"), QStringLiteral("587"), QStringLiteral("993"),
        QStringLiteral("995"),
    };
}

QStringList NetworkAnalysis::getFileSharingPorts() {
    return {
        QStringLiteral("20"), QStringLiteral("21"), QStringLiteral("22"),
        QStringLiteral("69"), QStringLiteral("139"), QStringLiteral("445"),
        QStringLiteral("2049"),
    };
}

QString NetworkAnalysis::getServiceName(int port) {
    static const QHash<int, QString> services = getPortServiceMap();
    return services.value(port, QStringLiteral("unknown"));
}

QHash<int, QString> NetworkAnalysis::getPortServiceMap() {
    return {
        {20, QStringLiteral("ftp-data")},
        {21, QStringLiteral("ftp")},
        {22, QStringLiteral("ssh")},
        {23, QStringLiteral("telnet")},
        {25, QStringLiteral("smtp")},
        {53, QStringLiteral("dns")},
        {67, QStringLiteral("dhcp-server")},
        {68, QStringLiteral("dhcp-client")},
        {69, QStringLiteral("tftp")},
        {80, QStringLiteral("http")},
        {110, QStringLiteral("pop3")},
        {119, QStringLiteral("nntp")},
        {123, QStringLiteral("ntp")},
        {135, QStringLiteral("msrpc")},
        {137, QStringLiteral("netbios-ns")},
        {138, QStringLiteral("netbios-dgm")},
        {139, QStringLiteral("netbios-ssn")},
        {143, QStringLiteral("imap")},
        {161, QStringLiteral("snmp")},
        {162, QStringLiteral("snmp-trap")},
        {179, QStringLiteral("bgp")},
        {389, QStringLiteral("ldap")},
        {443, QStringLiteral("https")},
        {445, QStringLiteral("smb")},
        {465, QStringLiteral("smtps")},
        {514, QStringLiteral("syslog")},
        {515, QStringLiteral("lpd")},
        {587, QStringLiteral("submission")},
        {636, QStringLiteral("ldaps")},
        {993, QStringLiteral("imaps")},
        {995, QStringLiteral("pop3s")},
        {1080, QStringLiteral("socks")},
        {1433, QStringLiteral("mssql")},
        {1434, QStringLiteral("mssql-browser")},
        {1521, QStringLiteral("oracle")},
        {1723, QStringLiteral("pptp")},
        {2049, QStringLiteral("nfs")},
        {2082, QStringLiteral("cpanel")},
        {2083, QStringLiteral("cpanel-ssl")},
        {2086, QStringLiteral("whm")},
        {2087, QStringLiteral("whm-ssl")},
        {3306, QStringLiteral("mysql")},
        {3389, QStringLiteral("rdp")},
        {3690, QStringLiteral("svn")},
        {5432, QStringLiteral("postgresql")},
        {5900, QStringLiteral("vnc")},
        {5985, QStringLiteral("winrm-http")},
        {5986, QStringLiteral("winrm-https")},
        {6379, QStringLiteral("redis")},
        {8000, QStringLiteral("http-alt")},
        {8080, QStringLiteral("http-proxy")},
        {8443, QStringLiteral("https-alt")},
        {8888, QStringLiteral("http-alt2")},
        {9090, QStringLiteral("web-console")},
        {9200, QStringLiteral("elasticsearch")},
        {9300, QStringLiteral("elasticsearch-transport")},
        {11211, QStringLiteral("memcached")},
        {27017, QStringLiteral("mongodb")},
        {27018, QStringLiteral("mongodb-shard")},
        {50000, QStringLiteral("sap")},
    };
}

bool NetworkAnalysis::isPrivateIP(const QString &ip) {
    QHostAddress addr(ip);
    if (addr.isNull()) return false;

    quint32 ipv4 = addr.toIPv4Address();
    if ((ipv4 & 0xFF000000) == 0x0A000000) return true;
    if ((ipv4 & 0xFFF00000) == 0xAC100000) return true;
    if ((ipv4 & 0xFFFF0000) == 0xC0A80000) return true;

    return false;
}

bool NetworkAnalysis::isLoopbackIP(const QString &ip) {
    QHostAddress addr(ip);
    return addr.isLoopback();
}

bool NetworkAnalysis::isMulticastIP(const QString &ip) {
    QHostAddress addr(ip);
    return addr.isMulticast();
}

bool NetworkAnalysis::isReservedIP(const QString &ip) {
    QHostAddress addr(ip);
    if (addr.isNull()) return false;

    quint32 ipv4 = addr.toIPv4Address();
    if ((ipv4 & 0xFF000000) == 0x00000000) return true;
    if ((ipv4 & 0xFF000000) == 0x7F000000) return true;
    if ((ipv4 & 0xFFFF0000) == 0xA9FE0000) return true;
    if ((ipv4 & 0xF0000000) == 0xE0000000) return true;
    if ((ipv4 & 0xF0000000) == 0xF0000000) return true;

    return false;
}

QString NetworkAnalysis::getIPClass(const QString &ip) {
    QHostAddress addr(ip);
    if (addr.isNull()) return QStringLiteral("Invalid");

    quint32 ipv4 = addr.toIPv4Address();
    quint8 firstOctet = (ipv4 >> 24) & 0xFF;

    if (firstOctet < 128) return QStringLiteral("Class A");
    if (firstOctet < 192) return QStringLiteral("Class B");
    if (firstOctet < 224) return QStringLiteral("Class C");
    if (firstOctet < 240) return QStringLiteral("Class D (Multicast)");
    return QStringLiteral("Class E (Reserved)");
}

QString NetworkAnalysis::getCIDRNotation(const QString &ip, const QString &subnet) {
    QHostAddress subnetAddr(subnet);
    if (subnetAddr.isNull()) return ip;

    quint32 mask = subnetAddr.toIPv4Address();
    int bits = 0;
    while (mask & 0x80000000) {
        bits++;
        mask <<= 1;
    }

    return QString(QStringLiteral("%1/%2")).arg(ip).arg(bits);
}

QStringList NetworkAnalysis::expandCIDR(const QString &cidr) {
    QStringList result;

    int slashPos = cidr.indexOf(QChar('/'));
    if (slashPos == -1) {
        result << cidr;
        return result;
    }

    QString ipPart = cidr.left(slashPos);
    int prefixLen = cidr.mid(slashPos + 1).toInt();

    if (prefixLen < 0 || prefixLen > 32) return result;
    if (prefixLen < 24) return result;

    QHostAddress addr(ipPart);
    if (addr.isNull()) return result;

    quint32 base = addr.toIPv4Address();
    quint32 mask = 0xFFFFFFFF << (32 - prefixLen);
    base &= mask;

    int hostCount = 1 << (32 - prefixLen);
    for (int i = 0; i < hostCount && i < 256; ++i) {
        QHostAddress host(base + i);
        result << host.toString();
    }

    return result;
}

QStringList NetworkAnalysis::parseHttpHeaders(const QString &rawHeaders) {
    return rawHeaders.split(QStringLiteral("\r\n"), Qt::SkipEmptyParts);
}

QHash<QString, QString> NetworkAnalysis::parseHeadersToMap(const QString &rawHeaders) {
    QHash<QString, QString> headers;
    const auto lines = rawHeaders.split(QStringLiteral("\r\n"), Qt::SkipEmptyParts);

    for (const QString &line : lines) {
        int colonPos = line.indexOf(QChar(':'));
        if (colonPos > 0) {
            QString key = line.left(colonPos).trimmed();
            QString value = line.mid(colonPos + 1).trimmed();
            headers[key] = value;
        }
    }

    return headers;
}

QString NetworkAnalysis::extractCookies(const QString &headers) {
    static const QRegularExpression cookieRegex(
        QStringLiteral("(?:Set-Cookie|Cookie):\\s*([^\\r\\n]+)"),
        QRegularExpression::CaseInsensitiveOption);

    QStringList cookies;
    auto matchIter = cookieRegex.globalMatch(headers);
    while (matchIter.hasNext()) {
        auto match = matchIter.next();
        cookies << match.captured(1);
    }

    return cookies.join(QStringLiteral("; "));
}

QStringList NetworkAnalysis::parseCookies(const QString &cookieString) {
    return cookieString.split(QStringLiteral("; "), Qt::SkipEmptyParts);
}

bool NetworkAnalysis::isValidUrl(const QString &url) {
    QUrl qurl(url);
    return qurl.isValid() && !qurl.scheme().isEmpty();
}

QString NetworkAnalysis::normalizeUrl(const QString &url) {
    QUrl qurl(url);
    if (!qurl.isValid()) return url;

    QString scheme = qurl.scheme().toLower();
    QString host = qurl.host().toLower();
    int port = qurl.port();
    QString path = qurl.path();

    if (path.isEmpty()) path = QStringLiteral("/");

    while (path.contains(QStringLiteral("//"))) {
        path.replace(QStringLiteral("//"), QStringLiteral("/"));
    }

    QString normalized = QString(QStringLiteral("%1://%2")).arg(scheme, host);

    if (port > 0 && !((scheme == QStringLiteral("http") && port == 80) ||
                       (scheme == QStringLiteral("https") && port == 443))) {
        normalized += QString(QStringLiteral(":%1")).arg(port);
    }

    normalized += path;

    if (qurl.hasQuery()) {
        normalized += QChar('?') + qurl.query();
    }

    return normalized;
}

QHash<QString, QString> NetworkAnalysis::parseUrlParameters(const QString &url) {
    QHash<QString, QString> params;
    QUrl qurl(url);

    if (qurl.hasQuery()) {
        QStringList pairs = qurl.query().split(QChar('&'), Qt::SkipEmptyParts);
        for (const QString &pair : pairs) {
            int eqPos = pair.indexOf(QChar('='));
            if (eqPos > 0) {
                QString key = QUrl::fromPercentEncoding(pair.left(eqPos).toUtf8());
                QString value = QUrl::fromPercentEncoding(pair.mid(eqPos + 1).toUtf8());
                params[key] = value;
            } else {
                params[pair] = QString();
            }
        }
    }

    return params;
}

QString NetworkAnalysis::buildUrl(const QString &base, const QHash<QString, QString> &params) {
    QUrl qurl(base);
    QStringList queryParts;

    for (auto it = params.constBegin(); it != params.constEnd(); ++it) {
        QString key = QUrl::toPercentEncoding(it.key());
        QString value = QUrl::toPercentEncoding(it.value());
        queryParts << QString(QStringLiteral("%1=%2")).arg(key, value);
    }

    if (!queryParts.isEmpty()) {
        qurl.setQuery(queryParts.join(QChar('&')));
    }

    return qurl.toString();
}

QStringList NetworkAnalysis::getSubdomains(const QString &domain) {
    return {
        QStringLiteral("www"),
        QStringLiteral("mail"),
        QStringLiteral("ftp"),
        QStringLiteral("admin"),
        QStringLiteral("api"),
        QStringLiteral("dev"),
        QStringLiteral("staging"),
        QStringLiteral("test"),
        QStringLiteral("beta"),
        QStringLiteral("portal"),
        QStringLiteral("secure"),
        QStringLiteral("login"),
        QStringLiteral("webmail"),
        QStringLiteral("smtp"),
        QStringLiteral("pop"),
        QStringLiteral("imap"),
        QStringLiteral("ns1"),
        QStringLiteral("ns2"),
        QStringLiteral("dns"),
        QStringLiteral("vpn"),
        QStringLiteral("remote"),
        QStringLiteral("intranet"),
        QStringLiteral("extranet"),
        QStringLiteral("wiki"),
        QStringLiteral("blog"),
        QStringLiteral("shop"),
        QStringLiteral("store"),
        QStringLiteral("cdn"),
        QStringLiteral("static"),
        QStringLiteral("assets"),
        QStringLiteral("media"),
        QStringLiteral("img"),
        QStringLiteral("images"),
        QStringLiteral("video"),
        QStringLiteral("files"),
        QStringLiteral("download"),
        QStringLiteral("upload"),
        QStringLiteral("cloud"),
        QStringLiteral("app"),
        QStringLiteral("mobile"),
        QStringLiteral("m"),
        QStringLiteral("forum"),
        QStringLiteral("support"),
        QStringLiteral("help"),
        QStringLiteral("kb"),
        QStringLiteral("docs"),
        QStringLiteral("status"),
        QStringLiteral("monitor"),
        QStringLiteral("dashboard"),
        QStringLiteral("cpanel"),
        QStringLiteral("whm"),
        QStringLiteral("webmin"),
        QStringLiteral("phpmyadmin"),
        QStringLiteral("mysql"),
        QStringLiteral("db"),
        QStringLiteral("database"),
        QStringLiteral("redis"),
        QStringLiteral("elastic"),
        QStringLiteral("kibana"),
        QStringLiteral("grafana"),
        QStringLiteral("prometheus"),
        QStringLiteral("jenkins"),
        QStringLiteral("gitlab"),
        QStringLiteral("git"),
        QStringLiteral("svn"),
        QStringLiteral("jira"),
        QStringLiteral("confluence"),
        QStringLiteral("bitbucket"),
        QStringLiteral("slack"),
        QStringLiteral("teams"),
        QStringLiteral("chat"),
        QStringLiteral("crm"),
        QStringLiteral("erp"),
        QStringLiteral("sso"),
        QStringLiteral("auth"),
        QStringLiteral("oauth"),
        QStringLiteral("identity"),
        QStringLiteral("iam"),
        QStringLiteral("ldap"),
        QStringLiteral("ad"),
        QStringLiteral("exchange"),
        QStringLiteral("owa"),
        QStringLiteral("autodiscover"),
        QStringLiteral("lyncdiscover"),
        QStringLiteral("sip"),
        QStringLiteral("meet"),
        QStringLiteral("conference"),
        QStringLiteral("video"),
        QStringLiteral("stream"),
        QStringLiteral("live"),
        QStringLiteral("radio"),
        QStringLiteral("tv"),
        QStringLiteral("news"),
        QStringLiteral("events"),
        QStringLiteral("calendar"),
        QStringLiteral("jobs"),
        QStringLiteral("careers"),
        QStringLiteral("hr"),
        QStringLiteral("payroll"),
    };
}

QString NetworkAnalysis::extractDomain(const QString &url) {
    QUrl qurl(url);
    return qurl.host();
}

QString NetworkAnalysis::extractTLD(const QString &domain) {
    int lastDot = domain.lastIndexOf(QChar('.'));
    if (lastDot > 0) {
        return domain.mid(lastDot + 1);
    }
    return domain;
}

bool NetworkAnalysis::isValidDomain(const QString &domain) {
    if (domain.isEmpty() || domain.length() > 253) return false;

    static const QRegularExpression domainRegex(
        QStringLiteral("^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*"
                       "[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"));

    return domainRegex.match(domain).hasMatch();
}

QStringList NetworkAnalysis::detectWAF(const QString &response, const QHash<QString, QString> &headers) {
    QStringList detected;

    struct WafSignature {
        QString name;
        QStringList headerPatterns;
        QStringList bodyPatterns;
    };

    static const QList<WafSignature> wafSignatures = {
        {QStringLiteral("Cloudflare"),
         {QStringLiteral("cf-ray"), QStringLiteral("__cfduid"), QStringLiteral("cf-cache-status")},
         {QStringLiteral("cloudflare"), QStringLiteral("cf-ray")}},
        {QStringLiteral("AWS WAF"),
         {QStringLiteral("x-amzn-requestid"), QStringLiteral("x-amz-cf-id")},
         {QStringLiteral("aws"), QStringLiteral("awselb")}},
        {QStringLiteral("Akamai"),
         {QStringLiteral("x-akamai-"), QStringLiteral("akamai")},
         {QStringLiteral("akamai"), QStringLiteral("aka")}},
        {QStringLiteral("Imperva"),
         {QStringLiteral("x-iinfo"), QStringLiteral("incap_ses")},
         {QStringLiteral("incapsula"), QStringLiteral("imperva")}},
        {QStringLiteral("F5 BIG-IP"),
         {QStringLiteral("x-wa-info"), QStringLiteral("bigipserver")},
         {QStringLiteral("big-ip"), QStringLiteral("f5")}},
        {QStringLiteral("Sucuri"),
         {QStringLiteral("x-sucuri-"), QStringLiteral("sucuri")},
         {QStringLiteral("sucuri"), QStringLiteral("cloudproxy")}},
        {QStringLiteral("ModSecurity"),
         {QStringLiteral("mod_security"), QStringLiteral("modsecurity")},
         {QStringLiteral("mod_security"), QStringLiteral("modsecurity")}},
        {QStringLiteral("Barracuda"),
         {QStringLiteral("barra_counter_session")},
         {QStringLiteral("barracuda")}},
        {QStringLiteral("Fortinet FortiWeb"),
         {QStringLiteral("fortiwafsid")},
         {QStringLiteral("fortiweb"), QStringLiteral("fortigate")}},
        {QStringLiteral("Citrix NetScaler"),
         {QStringLiteral("ns_af"), QStringLiteral("citrix_ns_id")},
         {QStringLiteral("netscaler"), QStringLiteral("citrix")}},
    };

    for (const auto &waf : wafSignatures) {
        bool found = false;

        for (const QString &pattern : waf.headerPatterns) {
            for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
                if (it.key().contains(pattern, Qt::CaseInsensitive) ||
                    it.value().contains(pattern, Qt::CaseInsensitive)) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        }

        if (!found) {
            for (const QString &pattern : waf.bodyPatterns) {
                if (response.contains(pattern, Qt::CaseInsensitive)) {
                    found = true;
                    break;
                }
            }
        }

        if (found) {
            detected << waf.name;
        }
    }

    return detected;
}

QStringList NetworkAnalysis::getWAFSignatures() {
    return {
        QStringLiteral("Cloudflare"), QStringLiteral("AWS WAF"), QStringLiteral("Akamai"),
        QStringLiteral("Imperva"), QStringLiteral("F5 BIG-IP"), QStringLiteral("Sucuri"),
        QStringLiteral("ModSecurity"), QStringLiteral("Barracuda"), QStringLiteral("Fortinet FortiWeb"),
        QStringLiteral("Citrix NetScaler"), QStringLiteral("DenyAll"), QStringLiteral("Radware"),
        QStringLiteral("SonicWall"), QStringLiteral("Comodo"), QStringLiteral("Wallarm"),
    };
}

QString NetworkAnalysis::detectWebServer(const QHash<QString, QString> &headers) {
    QString server = headers.value(QStringLiteral("Server"), QString());
    if (!server.isEmpty()) return server;

    server = headers.value(QStringLiteral("server"), QString());
    if (!server.isEmpty()) return server;

    if (headers.contains(QStringLiteral("X-Powered-By"))) {
        QString powered = headers.value(QStringLiteral("X-Powered-By"));
        if (powered.contains(QStringLiteral("ASP.NET"))) return QStringLiteral("IIS");
        if (powered.contains(QStringLiteral("PHP"))) return QStringLiteral("Apache/nginx (PHP)");
    }

    return QStringLiteral("Unknown");
}

QString NetworkAnalysis::detectFramework(const QString &response, const QHash<QString, QString> &headers) {
    QString powered = headers.value(QStringLiteral("X-Powered-By"), QString());
    if (powered.contains(QStringLiteral("Express"))) return QStringLiteral("Express.js");
    if (powered.contains(QStringLiteral("PHP"))) return QStringLiteral("PHP");
    if (powered.contains(QStringLiteral("ASP.NET"))) return QStringLiteral("ASP.NET");

    if (response.contains(QStringLiteral("__VIEWSTATE"))) return QStringLiteral("ASP.NET WebForms");
    if (response.contains(QStringLiteral("csrfmiddlewaretoken"))) return QStringLiteral("Django");
    if (response.contains(QStringLiteral("authenticity_token"))) return QStringLiteral("Ruby on Rails");
    if (response.contains(QStringLiteral("laravel_session"))) return QStringLiteral("Laravel");
    if (response.contains(QStringLiteral("__RequestVerificationToken"))) return QStringLiteral("ASP.NET MVC");
    if (response.contains(QStringLiteral("Symfony"))) return QStringLiteral("Symfony");
    if (response.contains(QStringLiteral("flask"))) return QStringLiteral("Flask");
    if (response.contains(QStringLiteral("spring"))) return QStringLiteral("Spring");

    return QStringLiteral("Unknown");
}

QStringList NetworkAnalysis::detectTechnologies(const QString &response, const QHash<QString, QString> &headers) {
    QStringList technologies;

    struct TechPattern {
        QString name;
        QString pattern;
    };

    static const QList<TechPattern> patterns = {
        {QStringLiteral("jQuery"), QStringLiteral("jquery")},
        {QStringLiteral("React"), QStringLiteral("react")},
        {QStringLiteral("Vue.js"), QStringLiteral("vue")},
        {QStringLiteral("Angular"), QStringLiteral("ng-app|angular")},
        {QStringLiteral("Bootstrap"), QStringLiteral("bootstrap")},
        {QStringLiteral("Tailwind CSS"), QStringLiteral("tailwind")},
        {QStringLiteral("Font Awesome"), QStringLiteral("fontawesome|font-awesome")},
        {QStringLiteral("Google Analytics"), QStringLiteral("google-analytics|gtag")},
        {QStringLiteral("Google Tag Manager"), QStringLiteral("googletagmanager")},
        {QStringLiteral("Hotjar"), QStringLiteral("hotjar")},
        {QStringLiteral("Intercom"), QStringLiteral("intercom")},
        {QStringLiteral("Zendesk"), QStringLiteral("zendesk")},
        {QStringLiteral("Stripe"), QStringLiteral("stripe")},
        {QStringLiteral("PayPal"), QStringLiteral("paypal")},
        {QStringLiteral("reCAPTCHA"), QStringLiteral("recaptcha")},
        {QStringLiteral("hCaptcha"), QStringLiteral("hcaptcha")},
        {QStringLiteral("Cloudflare"), QStringLiteral("cloudflare")},
        {QStringLiteral("WordPress"), QStringLiteral("wp-content|wordpress")},
        {QStringLiteral("Drupal"), QStringLiteral("drupal")},
        {QStringLiteral("Joomla"), QStringLiteral("joomla")},
        {QStringLiteral("Magento"), QStringLiteral("magento|mage")},
        {QStringLiteral("Shopify"), QStringLiteral("shopify")},
        {QStringLiteral("WooCommerce"), QStringLiteral("woocommerce")},
    };

    for (const auto &tech : patterns) {
        QRegularExpression regex(tech.pattern, QRegularExpression::CaseInsensitiveOption);
        if (regex.match(response).hasMatch()) {
            technologies << tech.name;
        }
    }

    QString server = detectWebServer(headers);
    if (!server.isEmpty() && server != QStringLiteral("Unknown")) {
        technologies << server;
    }

    QString framework = detectFramework(response, headers);
    if (!framework.isEmpty() && framework != QStringLiteral("Unknown")) {
        technologies << framework;
    }

    technologies.removeDuplicates();
    return technologies;
}

int NetworkAnalysis::calculateResponseTime(qint64 startMs, qint64 endMs) {
    return static_cast<int>(endMs - startMs);
}

QString NetworkAnalysis::categorizeResponseTime(int ms) {
    if (ms < 100) return QStringLiteral("Excellent");
    if (ms < 300) return QStringLiteral("Good");
    if (ms < 500) return QStringLiteral("Fair");
    if (ms < 1000) return QStringLiteral("Slow");
    return QStringLiteral("Very Slow");
}
