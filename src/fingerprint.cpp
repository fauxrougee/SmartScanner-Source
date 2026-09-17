#include "fingerprint.h"
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QFile>
#include <QTextStream>

namespace Fingerprint {

// Web server signatures
QList<ServerSignature> getServerSignatures() {
    return {
        // Apache
        {QStringLiteral("Apache"), QRegularExpression(QStringLiteral("Apache(/([\\d.]+))?")), QStringLiteral("server")},
        {QStringLiteral("Apache-Coyote"), QRegularExpression(QStringLiteral("Apache-Coyote/([\\d.]+)")), QStringLiteral("server")},

        // Nginx
        {QStringLiteral("nginx"), QRegularExpression(QStringLiteral("nginx(/([\\d.]+))?")), QStringLiteral("server")},
        {QStringLiteral("openresty"), QRegularExpression(QStringLiteral("openresty(/([\\d.]+))?")), QStringLiteral("server")},

        // Microsoft IIS
        {QStringLiteral("Microsoft-IIS"), QRegularExpression(QStringLiteral("Microsoft-IIS/([\\d.]+)")), QStringLiteral("server")},
        {QStringLiteral("Microsoft-HTTPAPI"), QRegularExpression(QStringLiteral("Microsoft-HTTPAPI/([\\d.]+)")), QStringLiteral("server")},

        // LiteSpeed
        {QStringLiteral("LiteSpeed"), QRegularExpression(QStringLiteral("LiteSpeed")), QStringLiteral("server")},

        // Cloudflare
        {QStringLiteral("cloudflare"), QRegularExpression(QStringLiteral("cloudflare")), QStringLiteral("server")},

        // Amazon
        {QStringLiteral("AmazonS3"), QRegularExpression(QStringLiteral("AmazonS3")), QStringLiteral("server")},
        {QStringLiteral("awselb"), QRegularExpression(QStringLiteral("awselb")), QStringLiteral("via")},

        // Tomcat
        {QStringLiteral("Tomcat"), QRegularExpression(QStringLiteral("Apache-Tomcat(/([\\d.]+))?")), QStringLiteral("server")},

        // Jetty
        {QStringLiteral("Jetty"), QRegularExpression(QStringLiteral("Jetty\\(([\\d.]+)\\)")), QStringLiteral("server")},

        // GWS (Google)
        {QStringLiteral("gws"), QRegularExpression(QStringLiteral("gws")), QStringLiteral("server")},

        // Express
        {QStringLiteral("Express"), QRegularExpression(QStringLiteral("Express")), QStringLiteral("x-powered-by")},

        // PHP
        {QStringLiteral("PHP"), QRegularExpression(QStringLiteral("PHP/([\\d.]+)")), QStringLiteral("x-powered-by")},

        // ASP.NET
        {QStringLiteral("ASP.NET"), QRegularExpression(QStringLiteral("ASP\\.NET")), QStringLiteral("x-powered-by")},
        {QStringLiteral("ASP.NET Core"), QRegularExpression(QStringLiteral("ASP\\.NET Core")), QStringLiteral("x-powered-by")},

        // Gunicorn
        {QStringLiteral("gunicorn"), QRegularExpression(QStringLiteral("gunicorn(/([\\d.]+))?")), QStringLiteral("server")},

        // uWSGI
        {QStringLiteral("uWSGI"), QRegularExpression(QStringLiteral("uWSGI(/([\\d.]+))?")), QStringLiteral("server")},

        // Werkzeug
        {QStringLiteral("Werkzeug"), QRegularExpression(QStringLiteral("Werkzeug(/([\\d.]+))?")), QStringLiteral("server")},

        // Caddy
        {QStringLiteral("Caddy"), QRegularExpression(QStringLiteral("Caddy")), QStringLiteral("server")},

        // Kestrel
        {QStringLiteral("Kestrel"), QRegularExpression(QStringLiteral("Kestrel")), QStringLiteral("server")},

        // Cowboy (Erlang)
        {QStringLiteral("Cowboy"), QRegularExpression(QStringLiteral("Cowboy")), QStringLiteral("server")},
    };
}

// CMS signatures from HTML
QList<CmsSignature> getCmsSignatures() {
    return {
        // WordPress
        {QStringLiteral("WordPress"), QRegularExpression(QStringLiteral("wp-content/themes/")), QStringLiteral("body")},
        {QStringLiteral("WordPress"), QRegularExpression(QStringLiteral("wp-includes/")), QStringLiteral("body")},
        {QStringLiteral("WordPress"), QRegularExpression(QStringLiteral("<meta name=\"generator\" content=\"WordPress")), QStringLiteral("body")},
        {QStringLiteral("WordPress"), QRegularExpression(QStringLiteral("/wp-json/")), QStringLiteral("body")},

        // Joomla
        {QStringLiteral("Joomla"), QRegularExpression(QStringLiteral("/administrator/")), QStringLiteral("body")},
        {QStringLiteral("Joomla"), QRegularExpression(QStringLiteral("<meta name=\"generator\" content=\"Joomla")), QStringLiteral("body")},
        {QStringLiteral("Joomla"), QRegularExpression(QStringLiteral("/media/jui/")), QStringLiteral("body")},

        // Drupal
        {QStringLiteral("Drupal"), QRegularExpression(QStringLiteral("Drupal\\.settings")), QStringLiteral("body")},
        {QStringLiteral("Drupal"), QRegularExpression(QStringLiteral("/sites/default/files/")), QStringLiteral("body")},
        {QStringLiteral("Drupal"), QRegularExpression(QStringLiteral("<meta name=\"generator\" content=\"Drupal")), QStringLiteral("body")},
        {QStringLiteral("Drupal"), QRegularExpression(QStringLiteral("X-Generator: Drupal")), QStringLiteral("headers")},

        // Magento
        {QStringLiteral("Magento"), QRegularExpression(QStringLiteral("/skin/frontend/")), QStringLiteral("body")},
        {QStringLiteral("Magento"), QRegularExpression(QStringLiteral("Mage\\.Cookies")), QStringLiteral("body")},
        {QStringLiteral("Magento"), QRegularExpression(QStringLiteral("/static/frontend/")), QStringLiteral("body")},

        // Shopify
        {QStringLiteral("Shopify"), QRegularExpression(QStringLiteral("Shopify\\.theme")), QStringLiteral("body")},
        {QStringLiteral("Shopify"), QRegularExpression(QStringLiteral("cdn\\.shopify\\.com")), QStringLiteral("body")},

        // Wix
        {QStringLiteral("Wix"), QRegularExpression(QStringLiteral("wix\\.com")), QStringLiteral("body")},
        {QStringLiteral("Wix"), QRegularExpression(QStringLiteral("static\\.wixstatic\\.com")), QStringLiteral("body")},

        // Squarespace
        {QStringLiteral("Squarespace"), QRegularExpression(QStringLiteral("Squarespace")), QStringLiteral("body")},
        {QStringLiteral("Squarespace"), QRegularExpression(QStringLiteral("static1\\.squarespace\\.com")), QStringLiteral("body")},

        // Ghost
        {QStringLiteral("Ghost"), QRegularExpression(QStringLiteral("<meta name=\"generator\" content=\"Ghost")), QStringLiteral("body")},

        // Hugo
        {QStringLiteral("Hugo"), QRegularExpression(QStringLiteral("<meta name=\"generator\" content=\"Hugo")), QStringLiteral("body")},

        // Jekyll
        {QStringLiteral("Jekyll"), QRegularExpression(QStringLiteral("<meta name=\"generator\" content=\"Jekyll")), QStringLiteral("body")},

        // Gatsby
        {QStringLiteral("Gatsby"), QRegularExpression(QStringLiteral("gatsby")), QStringLiteral("body")},
        {QStringLiteral("Gatsby"), QRegularExpression(QStringLiteral("___gatsby")), QStringLiteral("body")},

        // Next.js
        {QStringLiteral("Next.js"), QRegularExpression(QStringLiteral("__NEXT_DATA__")), QStringLiteral("body")},
        {QStringLiteral("Next.js"), QRegularExpression(QStringLiteral("/_next/")), QStringLiteral("body")},

        // Nuxt.js
        {QStringLiteral("Nuxt.js"), QRegularExpression(QStringLiteral("__NUXT__")), QStringLiteral("body")},
        {QStringLiteral("Nuxt.js"), QRegularExpression(QStringLiteral("/_nuxt/")), QStringLiteral("body")},

        // PrestaShop
        {QStringLiteral("PrestaShop"), QRegularExpression(QStringLiteral("prestashop")), QStringLiteral("body")},
        {QStringLiteral("PrestaShop"), QRegularExpression(QStringLiteral("/modules/ps_")), QStringLiteral("body")},

        // OpenCart
        {QStringLiteral("OpenCart"), QRegularExpression(QStringLiteral("catalog/view/theme/")), QStringLiteral("body")},

        // Typo3
        {QStringLiteral("Typo3"), QRegularExpression(QStringLiteral("typo3conf/")), QStringLiteral("body")},
        {QStringLiteral("Typo3"), QRegularExpression(QStringLiteral("<meta name=\"generator\" content=\"TYPO3")), QStringLiteral("body")},

        // Umbraco
        {QStringLiteral("Umbraco"), QRegularExpression(QStringLiteral("/umbraco/")), QStringLiteral("body")},

        // Sitecore
        {QStringLiteral("Sitecore"), QRegularExpression(QStringLiteral("/sitecore/")), QStringLiteral("body")},

        // Adobe Experience Manager
        {QStringLiteral("AEM"), QRegularExpression(QStringLiteral("/etc/clientlibs/")), QStringLiteral("body")},
        {QStringLiteral("AEM"), QRegularExpression(QStringLiteral("/content/dam/")), QStringLiteral("body")},

        // Contentful
        {QStringLiteral("Contentful"), QRegularExpression(QStringLiteral("contentful\\.com")), QStringLiteral("body")},

        // Strapi
        {QStringLiteral("Strapi"), QRegularExpression(QStringLiteral("/uploads/")), QStringLiteral("body")},
    };
}

// JavaScript framework signatures
QList<JsFrameworkSignature> getJsFrameworkSignatures() {
    return {
        // React
        {QStringLiteral("React"), QRegularExpression(QStringLiteral("react(?:\\.min)?\\.js")), QString()},
        {QStringLiteral("React"), QRegularExpression(QStringLiteral("data-reactroot")), QString()},
        {QStringLiteral("React"), QRegularExpression(QStringLiteral("__REACT_DEVTOOLS_GLOBAL_HOOK__")), QString()},

        // Angular
        {QStringLiteral("Angular"), QRegularExpression(QStringLiteral("ng-app")), QString()},
        {QStringLiteral("Angular"), QRegularExpression(QStringLiteral("angular(?:\\.min)?\\.js")), QString()},
        {QStringLiteral("Angular"), QRegularExpression(QStringLiteral("ng-version")), QString()},

        // Vue.js
        {QStringLiteral("Vue.js"), QRegularExpression(QStringLiteral("vue(?:\\.min)?\\.js")), QString()},
        {QStringLiteral("Vue.js"), QRegularExpression(QStringLiteral("v-bind")), QString()},
        {QStringLiteral("Vue.js"), QRegularExpression(QStringLiteral("data-v-[a-f0-9]+")), QString()},

        // jQuery
        {QStringLiteral("jQuery"), QRegularExpression(QStringLiteral("jquery(?:[.-]\\d+(?:\\.\\d+)*)?(?:\\.min)?\\.js")), QString()},

        // Bootstrap
        {QStringLiteral("Bootstrap"), QRegularExpression(QStringLiteral("bootstrap(?:\\.min)?\\.(?:js|css)")), QString()},
        {QStringLiteral("Bootstrap"), QRegularExpression(QStringLiteral("class=\"[^\"]*btn btn-")), QString()},

        // Backbone.js
        {QStringLiteral("Backbone.js"), QRegularExpression(QStringLiteral("backbone(?:\\.min)?\\.js")), QString()},

        // Ember.js
        {QStringLiteral("Ember.js"), QRegularExpression(QStringLiteral("ember(?:\\.min)?\\.js")), QString()},

        // Svelte
        {QStringLiteral("Svelte"), QRegularExpression(QStringLiteral("svelte")), QString()},

        // Tailwind CSS
        {QStringLiteral("Tailwind CSS"), QRegularExpression(QStringLiteral("tailwind(?:\\.min)?\\.css")), QString()},

        // Lodash
        {QStringLiteral("Lodash"), QRegularExpression(QStringLiteral("lodash(?:\\.min)?\\.js")), QString()},

        // Moment.js
        {QStringLiteral("Moment.js"), QRegularExpression(QStringLiteral("moment(?:\\.min)?\\.js")), QString()},

        // Axios
        {QStringLiteral("Axios"), QRegularExpression(QStringLiteral("axios(?:\\.min)?\\.js")), QString()},

        // D3.js
        {QStringLiteral("D3.js"), QRegularExpression(QStringLiteral("d3(?:\\.min)?\\.js")), QString()},

        // Three.js
        {QStringLiteral("Three.js"), QRegularExpression(QStringLiteral("three(?:\\.min)?\\.js")), QString()},

        // Socket.IO
        {QStringLiteral("Socket.IO"), QRegularExpression(QStringLiteral("socket\\.io(?:\\.min)?\\.js")), QString()},

        // Chart.js
        {QStringLiteral("Chart.js"), QRegularExpression(QStringLiteral("chart(?:\\.min)?\\.js")), QString()},

        // Highcharts
        {QStringLiteral("Highcharts"), QRegularExpression(QStringLiteral("highcharts(?:\\.min)?\\.js")), QString()},

        // Redux
        {QStringLiteral("Redux"), QRegularExpression(QStringLiteral("redux(?:\\.min)?\\.js")), QString()},

        // RxJS
        {QStringLiteral("RxJS"), QRegularExpression(QStringLiteral("rxjs")), QString()},

        // HTMX
        {QStringLiteral("HTMX"), QRegularExpression(QStringLiteral("htmx(?:\\.min)?\\.js")), QString()},
        {QStringLiteral("HTMX"), QRegularExpression(QStringLiteral("hx-(?:get|post|put|delete)")), QString()},

        // Alpine.js
        {QStringLiteral("Alpine.js"), QRegularExpression(QStringLiteral("alpine(?:\\.min)?\\.js")), QString()},
        {QStringLiteral("Alpine.js"), QRegularExpression(QStringLiteral("x-data")), QString()},
    };
}

// WAF signatures
QList<WafSignature> getWafSignatures() {
    return {
        // Cloudflare
        {QStringLiteral("Cloudflare"), QRegularExpression(QStringLiteral("cloudflare")), QStringLiteral("server"), QString()},
        {QStringLiteral("Cloudflare"), QRegularExpression(QStringLiteral("cf-ray")), QStringLiteral("headers"), QString()},
        {QStringLiteral("Cloudflare"), QRegularExpression(QStringLiteral("__cfduid")), QStringLiteral("cookies"), QString()},
        {QStringLiteral("Cloudflare"), QRegularExpression(QStringLiteral("Cloudflare Ray ID")), QStringLiteral("body"), QString()},

        // AWS WAF
        {QStringLiteral("AWS WAF"), QRegularExpression(QStringLiteral("x-amzn-waf-action")), QStringLiteral("headers"), QString()},
        {QStringLiteral("AWS WAF"), QRegularExpression(QStringLiteral("awswaf")), QStringLiteral("headers"), QString()},

        // Akamai
        {QStringLiteral("Akamai"), QRegularExpression(QStringLiteral("AkamaiGHost")), QStringLiteral("server"), QString()},
        {QStringLiteral("Akamai"), QRegularExpression(QStringLiteral("akamai")), QStringLiteral("server"), QString()},

        // ModSecurity
        {QStringLiteral("ModSecurity"), QRegularExpression(QStringLiteral("mod_security")), QStringLiteral("server"), QString()},
        {QStringLiteral("ModSecurity"), QRegularExpression(QStringLiteral("NOYB")), QStringLiteral("server"), QString()},

        // Imperva/Incapsula
        {QStringLiteral("Imperva"), QRegularExpression(QStringLiteral("X-Iinfo")), QStringLiteral("headers"), QString()},
        {QStringLiteral("Imperva"), QRegularExpression(QStringLiteral("incap_ses")), QStringLiteral("cookies"), QString()},
        {QStringLiteral("Imperva"), QRegularExpression(QStringLiteral("visid_incap")), QStringLiteral("cookies"), QString()},

        // F5 BIG-IP
        {QStringLiteral("F5 BIG-IP"), QRegularExpression(QStringLiteral("BigIP")), QStringLiteral("server"), QString()},
        {QStringLiteral("F5 BIG-IP"), QRegularExpression(QStringLiteral("BIGipServer")), QStringLiteral("cookies"), QString()},

        // Sucuri
        {QStringLiteral("Sucuri"), QRegularExpression(QStringLiteral("Sucuri")), QStringLiteral("server"), QString()},
        {QStringLiteral("Sucuri"), QRegularExpression(QStringLiteral("x-sucuri-id")), QStringLiteral("headers"), QString()},

        // Barracuda
        {QStringLiteral("Barracuda"), QRegularExpression(QStringLiteral("barra_counter_session")), QStringLiteral("cookies"), QString()},

        // Fortinet/FortiWeb
        {QStringLiteral("FortiWeb"), QRegularExpression(QStringLiteral("FORTIWAFSID")), QStringLiteral("cookies"), QString()},

        // Citrix NetScaler
        {QStringLiteral("Citrix NetScaler"), QRegularExpression(QStringLiteral("ns_af")), QStringLiteral("cookies"), QString()},
        {QStringLiteral("Citrix NetScaler"), QRegularExpression(QStringLiteral("citrix_ns_id")), QStringLiteral("cookies"), QString()},

        // Radware
        {QStringLiteral("Radware"), QRegularExpression(QStringLiteral("X-SL-CompState")), QStringLiteral("headers"), QString()},

        // Wallarm
        {QStringLiteral("Wallarm"), QRegularExpression(QStringLiteral("nginx-wallarm")), QStringLiteral("server"), QString()},

        // Wordfence (WordPress)
        {QStringLiteral("Wordfence"), QRegularExpression(QStringLiteral("wordfence")), QStringLiteral("body"), QString()},

        // DenyAll
        {QStringLiteral("DenyAll"), QRegularExpression(QStringLiteral("sessioncookie")), QStringLiteral("cookies"), QString()},

        // Comodo WAF
        {QStringLiteral("Comodo"), QRegularExpression(QStringLiteral("Protected by COMODO")), QStringLiteral("body"), QString()},

        // StackPath
        {QStringLiteral("StackPath"), QRegularExpression(QStringLiteral("X-SP-")), QStringLiteral("headers"), QString()},

        // KeyCDN
        {QStringLiteral("KeyCDN"), QRegularExpression(QStringLiteral("keycdn")), QStringLiteral("server"), QString()},
    };
}

// CDN signatures
QList<CdnSignature> getCdnSignatures() {
    return {
        {QStringLiteral("Cloudflare"), QRegularExpression(QStringLiteral("cf-ray")), QStringLiteral("headers")},
        {QStringLiteral("Cloudflare"), QRegularExpression(QStringLiteral("cf-cache-status")), QStringLiteral("headers")},
        {QStringLiteral("Akamai"), QRegularExpression(QStringLiteral("x-akamai-")), QStringLiteral("headers")},
        {QStringLiteral("AWS CloudFront"), QRegularExpression(QStringLiteral("x-amz-cf-")), QStringLiteral("headers")},
        {QStringLiteral("AWS CloudFront"), QRegularExpression(QStringLiteral("CloudFront")), QStringLiteral("via")},
        {QStringLiteral("Fastly"), QRegularExpression(QStringLiteral("x-fastly-")), QStringLiteral("headers")},
        {QStringLiteral("Fastly"), QRegularExpression(QStringLiteral("Fastly")), QStringLiteral("via")},
        {QStringLiteral("MaxCDN"), QRegularExpression(QStringLiteral("NetDNA")), QStringLiteral("server")},
        {QStringLiteral("KeyCDN"), QRegularExpression(QStringLiteral("keycdn")), QStringLiteral("server")},
        {QStringLiteral("Verizon EdgeCast"), QRegularExpression(QStringLiteral("ECS")), QStringLiteral("server")},
        {QStringLiteral("Microsoft Azure CDN"), QRegularExpression(QStringLiteral("x-azure-")), QStringLiteral("headers")},
        {QStringLiteral("Google Cloud CDN"), QRegularExpression(QStringLiteral("x-goog-")), QStringLiteral("headers")},
        {QStringLiteral("Imperva"), QRegularExpression(QStringLiteral("X-CDN")), QStringLiteral("headers")},
        {QStringLiteral("StackPath"), QRegularExpression(QStringLiteral("x-hw")), QStringLiteral("headers")},
        {QStringLiteral("Limelight"), QRegularExpression(QStringLiteral("x-llnw")), QStringLiteral("headers")},
    };
}

// Analytics signatures
QList<AnalyticsSignature> getAnalyticsSignatures() {
    return {
        {QStringLiteral("Google Analytics"), QRegularExpression(QStringLiteral("google-analytics\\.com/analytics\\.js")), QStringLiteral("script")},
        {QStringLiteral("Google Analytics"), QRegularExpression(QStringLiteral("googletagmanager\\.com/gtag/js")), QStringLiteral("script")},
        {QStringLiteral("Google Analytics"), QRegularExpression(QStringLiteral("ga\\s*\\(\\s*['\"]create")), QStringLiteral("inline")},
        {QStringLiteral("Google Tag Manager"), QRegularExpression(QStringLiteral("googletagmanager\\.com/gtm\\.js")), QStringLiteral("script")},
        {QStringLiteral("Facebook Pixel"), QRegularExpression(QStringLiteral("connect\\.facebook\\.net/.*/fbevents\\.js")), QStringLiteral("script")},
        {QStringLiteral("Facebook Pixel"), QRegularExpression(QStringLiteral("fbq\\s*\\(\\s*['\"]init")), QStringLiteral("inline")},
        {QStringLiteral("Hotjar"), QRegularExpression(QStringLiteral("static\\.hotjar\\.com")), QStringLiteral("script")},
        {QStringLiteral("Mixpanel"), QRegularExpression(QStringLiteral("cdn\\.mxpnl\\.com")), QStringLiteral("script")},
        {QStringLiteral("Segment"), QRegularExpression(QStringLiteral("cdn\\.segment\\.com")), QStringLiteral("script")},
        {QStringLiteral("Heap"), QRegularExpression(QStringLiteral("heap-analytics")), QStringLiteral("script")},
        {QStringLiteral("Amplitude"), QRegularExpression(QStringLiteral("cdn\\.amplitude\\.com")), QStringLiteral("script")},
        {QStringLiteral("Matomo/Piwik"), QRegularExpression(QStringLiteral("piwik\\.js")), QStringLiteral("script")},
        {QStringLiteral("Matomo/Piwik"), QRegularExpression(QStringLiteral("matomo\\.js")), QStringLiteral("script")},
        {QStringLiteral("Adobe Analytics"), QRegularExpression(QStringLiteral("omtrdc\\.net")), QStringLiteral("script")},
        {QStringLiteral("Clicky"), QRegularExpression(QStringLiteral("static\\.getclicky\\.com")), QStringLiteral("script")},
        {QStringLiteral("Plausible"), QRegularExpression(QStringLiteral("plausible\\.io")), QStringLiteral("script")},
        {QStringLiteral("Fathom"), QRegularExpression(QStringLiteral("cdn\\.usefathom\\.com")), QStringLiteral("script")},
    };
}

// Operating system detection from headers/errors
QList<OsSignature> getOsSignatures() {
    return {
        {QStringLiteral("Windows"), QRegularExpression(QStringLiteral("Win32|Win64|Windows")), QStringLiteral("any")},
        {QStringLiteral("Linux"), QRegularExpression(QStringLiteral("Linux|Ubuntu|Debian|CentOS|RHEL|Fedora")), QStringLiteral("any")},
        {QStringLiteral("macOS"), QRegularExpression(QStringLiteral("Darwin|macOS|Mac OS X")), QStringLiteral("any")},
        {QStringLiteral("FreeBSD"), QRegularExpression(QStringLiteral("FreeBSD")), QStringLiteral("any")},
        {QStringLiteral("OpenBSD"), QRegularExpression(QStringLiteral("OpenBSD")), QStringLiteral("any")},
        {QStringLiteral("Unix"), QRegularExpression(QStringLiteral("Unix|SunOS|Solaris")), QStringLiteral("any")},
    };
}

// Database detection from errors
QList<DatabaseSignature> getDatabaseSignatures() {
    return {
        {QStringLiteral("MySQL"), QRegularExpression(QStringLiteral("mysql|MariaDB")), QStringLiteral("error")},
        {QStringLiteral("PostgreSQL"), QRegularExpression(QStringLiteral("postgresql|pgsql|pg_")), QStringLiteral("error")},
        {QStringLiteral("Microsoft SQL Server"), QRegularExpression(QStringLiteral("mssql|sqlserver|SQL Server")), QStringLiteral("error")},
        {QStringLiteral("Oracle"), QRegularExpression(QStringLiteral("oracle|ORA-\\d+")), QStringLiteral("error")},
        {QStringLiteral("SQLite"), QRegularExpression(QStringLiteral("sqlite")), QStringLiteral("error")},
        {QStringLiteral("MongoDB"), QRegularExpression(QStringLiteral("mongodb")), QStringLiteral("error")},
        {QStringLiteral("Redis"), QRegularExpression(QStringLiteral("redis")), QStringLiteral("error")},
        {QStringLiteral("Cassandra"), QRegularExpression(QStringLiteral("cassandra")), QStringLiteral("error")},
        {QStringLiteral("Elasticsearch"), QRegularExpression(QStringLiteral("elasticsearch")), QStringLiteral("error")},
        {QStringLiteral("CouchDB"), QRegularExpression(QStringLiteral("couchdb")), QStringLiteral("error")},
    };
}

// Main fingerprinting function
FingerprintResult fingerprint(const QString &body, const QMap<QString, QString> &headers) {
    FingerprintResult result;

    // Check server headers
    QString server = headers.value(QStringLiteral("server"));
    for (const auto &sig : getServerSignatures()) {
        if (!server.isEmpty()) {
            auto match = sig.pattern.match(server);
            if (match.hasMatch()) {
                DetectedTech tech;
                tech.name = sig.name;
                tech.version = match.captured(1);
                tech.confidence = 0.9;
                tech.category = QStringLiteral("server");
                result.technologies.append(tech);
            }
        }
    }

    // Check CMS signatures
    for (const auto &sig : getCmsSignatures()) {
        if (sig.location == QStringLiteral("body")) {
            auto match = sig.pattern.match(body);
            if (match.hasMatch()) {
                DetectedTech tech;
                tech.name = sig.name;
                tech.confidence = 0.8;
                tech.category = QStringLiteral("cms");
                bool found = false;
                for (const auto &existing : result.technologies) {
                    if (existing.name == tech.name && existing.category == tech.category) {
                        found = true;
                        break;
                    }
                }
                if (!found) result.technologies.append(tech);
            }
        }
    }

    // Check JS framework signatures
    for (const auto &sig : getJsFrameworkSignatures()) {
        auto match = sig.pattern.match(body);
        if (match.hasMatch()) {
            DetectedTech tech;
            tech.name = sig.name;
            tech.version = match.captured(1);
            tech.confidence = 0.7;
            tech.category = QStringLiteral("javascript");
            bool found = false;
            for (const auto &existing : result.technologies) {
                if (existing.name == tech.name && existing.category == tech.category) {
                    found = true;
                    break;
                }
            }
            if (!found) result.technologies.append(tech);
        }
    }

    // Check WAF signatures
    for (const auto &sig : getWafSignatures()) {
        bool matched = false;
        if (sig.location == QStringLiteral("server")) {
            matched = sig.pattern.match(server).hasMatch();
        } else if (sig.location == QStringLiteral("headers")) {
            for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
                if (sig.pattern.match(it.key()).hasMatch() || sig.pattern.match(it.value()).hasMatch()) {
                    matched = true;
                    break;
                }
            }
        } else if (sig.location == QStringLiteral("body")) {
            matched = sig.pattern.match(body).hasMatch();
        }

        if (matched) {
            DetectedTech tech;
            tech.name = sig.name;
            tech.confidence = 0.85;
            tech.category = QStringLiteral("waf");
            bool found = false;
            for (const auto &existing : result.technologies) {
                if (existing.name == tech.name && existing.category == tech.category) {
                    found = true;
                    break;
                }
            }
            if (!found) result.technologies.append(tech);
        }
    }

    // Check CDN signatures
    for (const auto &sig : getCdnSignatures()) {
        bool matched = false;
        for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
            if (sig.pattern.match(it.key()).hasMatch() || sig.pattern.match(it.value()).hasMatch()) {
                matched = true;
                break;
            }
        }

        if (matched) {
            DetectedTech tech;
            tech.name = sig.name;
            tech.confidence = 0.9;
            tech.category = QStringLiteral("cdn");
            bool found = false;
            for (const auto &existing : result.technologies) {
                if (existing.name == tech.name && existing.category == tech.category) {
                    found = true;
                    break;
                }
            }
            if (!found) result.technologies.append(tech);
        }
    }

    // Check analytics signatures
    for (const auto &sig : getAnalyticsSignatures()) {
        auto match = sig.pattern.match(body);
        if (match.hasMatch()) {
            DetectedTech tech;
            tech.name = sig.name;
            tech.confidence = 0.85;
            tech.category = QStringLiteral("analytics");
            bool found = false;
            for (const auto &existing : result.technologies) {
                if (existing.name == tech.name && existing.category == tech.category) {
                    found = true;
                    break;
                }
            }
            if (!found) result.technologies.append(tech);
        }
    }

    return result;
}

} // namespace Fingerprint
