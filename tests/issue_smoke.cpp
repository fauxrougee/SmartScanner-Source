#include "issue.h"
#include "indexseed.h"
#include "issuedb.h"
#include "issuedbstream.h"
#include "httprequestrawpacket.h"
#include "httpclient.h"
#include "htmlnumericentity.h"
#include "fileliststream.h"
#include "filecountconstrain.h"
#include "dircountconstrain.h"
#include "crawlerformexpressions.h"
#include "crawlerformparser.h"
#include "crawlerparsehelpers.h"
#include "crawlerscriptparser.h"
#include "crawlerhtmlparser.h"
#include "crawlerrequestitem.h"
#include "directoryrootseed.h"
#include "filelist.h"
#include "filelisturlheuristic.h"
#include "filelistqueryfilter.h"
#include "filelistquerystate.h"
#include "scanner.h"
#include "requestitemstream.h"
#include "requestmanager.h"
#include "robottxtparser.h"
#include "sitemapseed.h"
#include "sitemaplocation.h"
#include "sitemapxmlparser.h"
#include "smspformat.h"
#include "threadsafecookiejar.h"
#include "urlnormalizer.h"

#include <QCryptographicHash>

#include <QBuffer>
#include <QAuthenticator>
#include <QCoreApplication>
#include <QMetaObject>
#include <QNetworkReply>
#include <QNetworkRequest>

#include <cstring>
#include <utility>

// Test-only access to the original body helper. Full completion requires the
// native reply/waiter registry; these memory fixtures intentionally do not submit.
struct RequestManagerNativeTestAccess {
    static void storeBody(RequestManager &manager, QNetworkReply *reply) {
        manager.storeReplyBody(reply);
    }
};

namespace {

class MemoryReply final : public QNetworkReply {
public:
    MemoryReply(const QNetworkRequest &request, QByteArray payload)
        : m_payload(std::move(payload))
    {
        setRequest(request);
        open(QIODevice::ReadOnly);
        setFinished(true);
    }

    void abort() override {}

    qint64 bytesAvailable() const override
    {
        return m_payload.size() - m_offset + QNetworkReply::bytesAvailable();
    }

protected:
    qint64 readData(char *data, qint64 maximumSize) override
    {
        const qint64 count = qMin(maximumSize, m_payload.size() - m_offset);
        if (count <= 0)
            return 0;
        memcpy(data, m_payload.constData() + m_offset, static_cast<size_t>(count));
        m_offset += count;
        return count;
    }

private:
    QByteArray m_payload;
    qint64 m_offset = 0;
};

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    Issue issue;
    issue.field00 = QStringLiteral("first");
    issue.field18 = QStringLiteral("issue-name");
    issue.field30 = QUrl(QStringLiteral("https://example.invalid/path"));
    issue.fieldA0 = 3;
    issue.fieldD8.append({QStringLiteral("key"), QStringLiteral("value")});
    issue.fieldF0.append({QByteArrayLiteral("request"), QByteArrayLiteral("response")});
    issue.field108.insert(QStringLiteral("custom"), {QStringLiteral("one"), QStringLiteral("two")});
    issue.field118.append(QStringLiteral("reference"));
    issue.field250 = 0x1020304050607080ULL;

    IssueDbStreamState original;
    original.field2A0.append(issue);
    original.field2B8.insert(123456789, issue);
    original.field2B8.insert(123456789, issue);
    original.field2C8.insert(QUrl(QStringLiteral("https://example.invalid/")));

    QByteArray bytes;
    QBuffer writeDevice(&bytes);
    writeDevice.open(QIODevice::WriteOnly);
    QDataStream writer(&writeDevice);
    writer.setVersion(QDataStream::Qt_6_7);
    writer << original;
    if (writer.status() != QDataStream::Ok)
        return 1;

    IssueDbStreamState decoded;
    QBuffer readDevice(&bytes);
    readDevice.open(QIODevice::ReadOnly);
    QDataStream reader(&readDevice);
    reader.setVersion(QDataStream::Qt_6_7);
    reader >> decoded;
    if (reader.status() != QDataStream::Ok || decoded.field2A0.size() != 1
        || decoded.field2B8.size() != 2 || decoded.field2C8.size() != 1)
        return 2;

    const Issue &loaded = decoded.field2A0.first();
    if (loaded.field18 != issue.field18 || loaded.field30 != issue.field30
        || loaded.fieldD8 != issue.fieldD8 || loaded.fieldF0 != issue.fieldF0
        || loaded.field108 != issue.field108 || loaded.field250 != issue.field250)
        return 3;

    if (UrlNormalizer::withoutDefaultPort(QUrl(QStringLiteral("http://example.invalid:80/"))).port(-1) != -1
        || UrlNormalizer::withoutDefaultPort(QUrl(QStringLiteral("https://example.invalid:443/"))).port(-1) != -1
        || UrlNormalizer::withoutDefaultPort(QUrl(QStringLiteral("http://example.invalid:8080/"))).port(-1) != 8080)
        return 4;

    if (UrlNormalizer::withoutUnqueriedRootSlash(QUrl(QStringLiteral("https://example.invalid/"))).toString()
            != QStringLiteral("https://example.invalid")
        || UrlNormalizer::withoutUnqueriedRootSlash(QUrl(QStringLiteral("https://example.invalid/?q=1"))).toString()
            != QStringLiteral("https://example.invalid/?q=1"))
        return 5;

    if (UrlNormalizer::withoutDefaultDocument(QUrl(QStringLiteral("https://example.invalid/INDEX.HTML?q=1"))).toString()
            != QStringLiteral("https://example.invalid/?q=1")
        || UrlNormalizer::withoutDefaultDocument(QUrl(QStringLiteral("https://example.invalid/login.html"))).toString()
            != QStringLiteral("https://example.invalid/login.html"))
        return 6;

    if (UrlNormalizer::withSortedQueryItems(QUrl(QStringLiteral("https://example.invalid/?z=1&a=2"))).query()
            != QStringLiteral("a=2&z=1"))
        return 7;

    if (UrlNormalizer::canonicalForIssue(QUrl(QStringLiteral("HTTPS://WWW.Example.invalid:443/a/../index.html?q=1#part")))
            != QStringLiteral("https://example.invalid"))
        return 8;

    if (UrlNormalizer::canonical(QUrl(QStringLiteral("HTTPS://WWW.Example.invalid:443/a/../index.html?z=1&a=2#part")), 15)
            != QStringLiteral("https://example.invalid/?a=2&z=1"))
        return 24;

    Issue sameIdentityA;
    sameIdentityA.field18 = QStringLiteral("name");
    sameIdentityA.field70 = QStringLiteral("detail");
    sameIdentityA.fieldA0 = 3;
    sameIdentityA.field30 = QUrl(QStringLiteral("https://www.example.invalid/index.html?first=1"));
    Issue sameIdentityB;
    sameIdentityB.field18 = sameIdentityA.field18;
    sameIdentityB.field70 = sameIdentityA.field70;
    sameIdentityB.fieldA0 = sameIdentityA.fieldA0;
    sameIdentityB.field30 = QUrl(QStringLiteral("https://example.invalid/?second=2"));
    Issue noIdentity;
    if (sameIdentityA.identity() == 0 || sameIdentityA.identity() != sameIdentityB.identity()
        || noIdentity.identity() != 0)
        return 9;

    IssueDb db;
    int adds = 0;
    int updates = 0;
    QObject::connect(&db, &IssueDb::newIssueAdded, [&adds](const Issue &) { ++adds; });
    QObject::connect(&db, &IssueDb::issueUpdated, [&updates] { ++updates; });
    if (!db.add(sameIdentityA) || db.add(sameIdentityB) || adds != 1
        || !db.addOrUpdate(sameIdentityB) || updates != 1
        || db.removeByUrl(QStringLiteral("https://example.invalid/?second=2")) != 1
        || updates != 2 || !db.issues().isEmpty())
        return 10;

    urlItem originalUrlItem;
    originalUrlItem.target = QStringLiteral("https://example.invalid/path?x=1");
    originalUrlItem.field20 = 7;
    originalUrlItem.field28 = QByteArrayLiteral("payload");
    originalUrlItem.headers[QByteArrayLiteral("x-test")].append(
        qMakePair(QByteArrayLiteral("X-Test"), QByteArrayLiteral("value")));
    originalUrlItem.headers[QByteArrayLiteral("x-test")].append(
        qMakePair(QByteArrayLiteral("X-Test"), QByteArrayLiteral("second-value")));
    originalUrlItem.field50 = 19;
    originalUrlItem.field58 = 42;
    originalUrlItem.field60 = 9876543210LL;
    originalUrlItem.field68 = 4;
    originalUrlItem.field6C = 77;
    originalUrlItem.field70 = QStringLiteral("observed");
    originalUrlItem.field88 = 6;
    originalUrlItem.field8C = 12;
    originalUrlItem.field90 = 34;
    originalUrlItem.field94 = true;

    QByteArray urlItemBytes;
    QBuffer urlItemWriterDevice(&urlItemBytes);
    urlItemWriterDevice.open(QIODevice::WriteOnly);
    QDataStream urlItemWriter(&urlItemWriterDevice);
    urlItemWriter.setVersion(QDataStream::Qt_6_7);
    HttpRequestItem &virtualWriter = originalUrlItem;
    virtualWriter.writeToStream(urlItemWriter);
    urlItem decodedUrlItem;
    QBuffer urlItemReaderDevice(&urlItemBytes);
    urlItemReaderDevice.open(QIODevice::ReadOnly);
    QDataStream urlItemReader(&urlItemReaderDevice);
    urlItemReader.setVersion(QDataStream::Qt_6_7);
    HttpRequestItem &virtualReader = decodedUrlItem;
    int extensionSentinel = 123;
    originalUrlItem.setExtensionFrom(&extensionSentinel);
    if (virtualWriter.streamTypeName() != QStringLiteral("urlItem")
        || originalUrlItem.field28Copy() != originalUrlItem.field28
        || extensionSentinel != 123)
        return 11;

    const urlItem factoryItem(QStringLiteral("https://example.invalid/factory"), 7,
                              QByteArrayLiteral("body=value"));
    if (factoryItem.target != QStringLiteral("https://example.invalid/factory")
        || factoryItem.field20 != 7 || factoryItem.field28 != QByteArrayLiteral("body=value")
        || factoryItem.field58 != 0 || factoryItem.field6C != 0 || factoryItem.field88 != 5)
        return 36;

    urlItem standardHeaderItem;
    standardHeaderItem.setStandardHeader(HttpRequestItem::StandardHeader::Referer,
                                         QByteArrayLiteral("https://first.invalid/"));
    standardHeaderItem.setStandardHeader(HttpRequestItem::StandardHeader::Referer,
                                         QByteArrayLiteral("https://second.invalid/"));
    const auto refererHeaders = standardHeaderItem.headers.value(QByteArrayLiteral("referer"));
    if (HttpRequestItem::standardHeaderName(HttpRequestItem::StandardHeader::AcceptLanguage)
            != QByteArrayLiteral("Accept-Language")
        || refererHeaders.size() != 1 || refererHeaders.first().first != QByteArrayLiteral("Referer")
        || refererHeaders.first().second != QByteArrayLiteral("https://second.invalid/"))
        return 42;

    const auto sitemapItem = makeSitemapSeedRequest(
        QStringLiteral("https://example.invalid/old/path?token=one#section"), 9988);
    if (!sitemapItem || sitemapItem->url().toString() != QStringLiteral("https://example.invalid/sitemap.xml")
        || sitemapItem->field20 != 1 || !sitemapItem->field28.isEmpty()
        || sitemapItem->field60 != 9988 || sitemapItem->field6C != 1 || !sitemapItem->field94)
        return 41;

    const auto discoveredSitemapItem = makeSitemapDiscoveredRequest(
        QUrl(QStringLiteral("https://example.invalid/from-sitemap?part=1")), 4, 7766);
    if (!discoveredSitemapItem || discoveredSitemapItem->target
            != QStringLiteral("https://example.invalid/from-sitemap?part=1")
        || discoveredSitemapItem->field20 != 1 || discoveredSitemapItem->field60 != 7766
        || discoveredSitemapItem->field6C != 4 || !discoveredSitemapItem->field94)
        return 45;

    if (resolveDecodedSitemapLocation(
            QUrl(QStringLiteral("https://example.invalid/dir/sitemap.xml")),
            QStringLiteral("  ../assets\\page.html  ")).toString()
            != QStringLiteral("https://example.invalid/assets/page.html"))
        return 46;

    if (resolveSitemapLocation(QUrl(QStringLiteral("https://example.invalid/dir/sitemap.xml")),
                               QStringLiteral("../a&amp;b.html"))
            != QUrl(QStringLiteral("https://example.invalid/a&b.html")))
        return 58;

    if (crawlerFirstElementAttribute(
            QStringLiteral("<BASE data-x='one' HREF='https://cdn.example.invalid/assets/'>"),
            QStringLiteral("base"), QStringLiteral("href"))
            != QStringLiteral("https://cdn.example.invalid/assets/")
        || crawlerFirstElementAttribute(QStringLiteral("<base href=>"), QStringLiteral("base"),
                                        QStringLiteral("href"))
               != QString()
        || crawlerDocumentBaseUrl(QUrl(QStringLiteral("https://example.invalid/dir/page.html")),
                                  QStringLiteral("<base href='../assets/'>"))
               != QUrl(QStringLiteral("https://example.invalid/assets/")))
        return 62;

    const QString xmlAttributeValue = crawlerFirstElementAttributeOrFallback(
        QStringLiteral("<root><input value=\"from-dom\"/></root>"), QStringLiteral("input"),
        QStringLiteral("value"), QStringLiteral("fallback"));
    const QString regexAttributeValue = crawlerFirstElementAttributeOrFallback(
        QStringLiteral("<input value='from-regex'>"), QStringLiteral("input"),
        QStringLiteral("value"), QStringLiteral("fallback"));
    const QString bareAttributeValue = crawlerFirstElementAttributeOrFallback(
        QStringLiteral("<input value=>"), QStringLiteral("input"), QStringLiteral("value"),
        QStringLiteral("fallback"));
    const QString absentAttributeValue = crawlerFirstElementAttributeOrFallback(
        QStringLiteral("<input name='only-name'>"), QStringLiteral("input"),
        QStringLiteral("value"), QStringLiteral("fallback"));
    if (xmlAttributeValue != QStringLiteral("from-dom")
        || regexAttributeValue != QStringLiteral("from-regex")
        || bareAttributeValue != QStringLiteral("fallback") || !absentAttributeValue.isNull())
        return 72;

    if (crawlerFormTextContent(QStringLiteral("<label>  First <b> value </b></label>"))
        != QStringLiteral("First value"))
        return 73;

    if (crawlerFormExpression().pattern()
            != QStringLiteral(R"(<form(\s[^>]*?)*?>([\s\S]*?)</form>)")
        || crawlerInputExpression().pattern() != QStringLiteral(R"(<input(\s[^>]*?)*?>)")
        || crawlerSelectExpression().pattern()
               != QStringLiteral(R"(<select(\s[^>]*?)*?>([\s\S]*?)</select>)")
        || crawlerTextareaExpression().pattern()
               != QStringLiteral(R"(<textarea(\s[^>]*?)*?>([\s\S]*?)</textarea>)")
        || crawlerOptionExpression().pattern() != QStringLiteral(R"(<option(\s[^>]*?)*?>)")
        || crawlerFormAttributeExpression().pattern()
               != QStringLiteral(R"(([^\s]+)\s*=\s*((?:"[^"]+")|(?:'[^']+')|(?:[^'">\s]+)))")
        || crawlerFormExpression().patternOptions()
               != QRegularExpression::CaseInsensitiveOption)
        return 173;

    const QList<HtmlForm> recoveredForms = crawlerHtmlForms(
        QUrl(QStringLiteral("https://example.invalid/dir/page.html")),
        QStringLiteral("<form action='../save' method='POST' enctype='MULTIPART/form-data'>"
                       "<input name='username' value='alice' type='text' checked data-id=42>"
                       "<input name='skip' type='reset'>"
                       "<input name='' value='also-skip'>"
                       "<select name='choice'><option value='first'><option value='second' selected>"
                       "</select><textarea name='bio'>about</textarea></form>"
                       "<form action='/find'><input name='q'></form>"));
    if (recoveredForms.size() != 2)
        return 174;
    if (recoveredForms.at(0).target != QStringLiteral("https://example.invalid/save"))
        return 175;
    if (recoveredForms.at(0).field20 != 2)
        return 176;
    if (recoveredForms.at(0).headers.value(QByteArrayLiteral("referer")).constFirst().second
        != QByteArrayLiteral("https://example.invalid/dir/page.html"))
        return 177;
    if (recoveredForms.at(0).headers.value(QByteArrayLiteral("content-type")).constFirst().second
        != QByteArrayLiteral("multipart/form-data"))
        return 178;
    if (recoveredForms.at(0).field98.size() != 3)
        return 179;
    if (recoveredForms.at(0).field98.at(0).field00 != QStringLiteral("username")
        || recoveredForms.at(0).field98.at(0).field18 != QStringLiteral("alice")
        || recoveredForms.at(0).field98.at(0).field30 != QStringLiteral("text")
        || !recoveredForms.at(0).field98.at(0).field78
        || recoveredForms.at(0).field98.at(0).field98.value(QStringLiteral("data-id"))
               != QStringLiteral("42"))
        return 180;
    if (recoveredForms.at(0).field98.at(1).field00 != QStringLiteral("choice")
        || recoveredForms.at(0).field98.at(1).field18 != QStringLiteral("second"))
        return 181;
    if (recoveredForms.at(0).field98.at(2).field00 != QStringLiteral("bio")
        || recoveredForms.at(0).field98.at(2).field18 != QStringLiteral("about")
        || recoveredForms.at(0).field98.at(2).field30 != QStringLiteral("textarea"))
        return 182;
    if (recoveredForms.at(1).target != QStringLiteral("https://example.invalid/find")
        || recoveredForms.at(1).field20 != 1 || recoveredForms.at(1).field98.size() != 1)
        return 183;

    const QString scriptDocument = QStringLiteral(
        "<script src='/good.js' type='module'></script>"
        "<script src='javascript:blocked.js'></script>"
        "<script src='https://google-analytics.com/ignored.js'></script>"
        "<script>var inlineValue = 1;</script><a onclick=\"go()\">x</a>");
    const CrawlerScriptParseResult scriptResult = crawlerParseScripts(
        QUrl(QStringLiteral("https://example.invalid/dir/page.html")), scriptDocument);
    QCryptographicHash expectedScriptFingerprint(QCryptographicHash::Sha1);
    expectedScriptFingerprint.addData(QByteArrayLiteral("https://example.invalid/good.js"));
    expectedScriptFingerprint.addData(QByteArrayLiteral("var inlineValue = 1;"));
    expectedScriptFingerprint.addData(QByteArrayLiteral("javascript:blocked.js'"));
    expectedScriptFingerprint.addData(QByteArrayLiteral("onclick=\"go()\""));
    if (scriptResult.sourceLocations
        != QList<QUrl>{QUrl(QStringLiteral("https://example.invalid/good.js"))})
        return 184;
    if (scriptResult.fingerprint != expectedScriptFingerprint.result().toHex())
        return 185;
    if (!crawlerAnalyticsScriptExpression().match(QStringLiteral("GTag/js")).hasMatch())
        return 186;
    if (!crawlerScriptEventExpression().match(QStringLiteral("javascript:alert(1)")).hasMatch())
        return 187;

    const HtmlFormInput recoveredSelect = crawlerSelectInputFromOptionFragments(
        QStringLiteral("<select name='mode'>"),
        {QStringLiteral("<option value='first'>"),
         QStringLiteral("<option value='second' selected='false'>"),
         QStringLiteral("<option value='third' selected>")});
    if (recoveredSelect.field00 != QStringLiteral("mode")
        || recoveredSelect.field30 != QStringLiteral("select")
        || recoveredSelect.field48
               != QList<QString>{QStringLiteral("first"), QStringLiteral("second"),
                                  QStringLiteral("third")}
        || recoveredSelect.field18 != QStringLiteral("third")
        || recoveredSelect.field60
               != QList<QString>{QStringLiteral("third")})
        return 74;

    QNetworkRequest replyRequest(QUrl(QStringLiteral("https://example.invalid/reply")));
    RequestManager requestManager;
    MemoryReply memoryReply(replyRequest, QByteArray(250000, 'x'));
    RequestManagerNativeTestAccess::storeBody(requestManager, &memoryReply);
    if (memoryReply.property("body").toByteArray().size() != 204800
        || !memoryReply.property("partial").toBool() || memoryReply.bytesAvailable() != 0
        || requestManager.totalReceivedBytes() != 250000)
        return 76;

    QNetworkRequest extendedReplyRequest(QUrl(QStringLiteral("https://example.invalid/extended")));
    extendedReplyRequest.setAttribute(static_cast<QNetworkRequest::Attribute>(1011), 2048);
    MemoryReply extendedMemoryReply(extendedReplyRequest, QByteArray(250000, 'y'));
    RequestManagerNativeTestAccess::storeBody(requestManager, &extendedMemoryReply);
    if (extendedMemoryReply.property("body").toByteArray().size() != 250000
        || extendedMemoryReply.property("partial").isValid()
        || extendedMemoryReply.bytesAvailable() != 0
        || requestManager.totalReceivedBytes() != 500000)
        return 78;

    QNetworkRequest credentialRequest(QUrl(QStringLiteral("https://example.invalid/auth")));
    credentialRequest.setAttribute(static_cast<QNetworkRequest::Attribute>(1009),
                                   QStringLiteral("alice||secret"));
    MemoryReply credentialReply(credentialRequest, {});
    QAuthenticator authenticator;
    authenticator.setUser(QStringLiteral("different"));
    authenticator.setPassword(QStringLiteral("different"));
    if (!QMetaObject::invokeMethod(&requestManager, "authenticate", Qt::DirectConnection,
                                   Q_ARG(QNetworkReply *, &credentialReply),
                                   Q_ARG(QAuthenticator *, &authenticator)))
        return 79;
    if (authenticator.user() != QStringLiteral("alice")
        || authenticator.password() != QStringLiteral("secret"))
        return 80;

    NetworkManager networkManager{QString()};
    QAuthenticator networkAuthenticator;
    if (!QMetaObject::invokeMethod(&networkManager, "authenticate", Qt::DirectConnection,
                                   Q_ARG(QNetworkReply *, &credentialReply),
                                   Q_ARG(QAuthenticator *, &networkAuthenticator)))
        return 81;
    if (networkAuthenticator.user() != QStringLiteral("alice")
        || networkAuthenticator.password() != QStringLiteral("secret"))
        return 82;
    if (networkManager.concurrentLimit() != 5 || !networkManager.isIdle()
        || networkManager.activeRequests() != 0 || networkManager.queuedRequests() != 0
        || networkManager.totalRequests() != 0 || networkManager.completedRequests() != 0
        || !networkManager.lastUrl().isEmpty())
        return 83;

    HttpRequestRawPacket rawPacket;
    rawPacket.target = QStringLiteral("https://example.invalid/path?item=one#fragment");
    rawPacket.field20 = 2;
    rawPacket.field28 = QByteArrayLiteral("body");
    rawPacket.protocol = QByteArrayLiteral("HTTP/1.1");
    rawPacket.setHeader(QByteArrayLiteral("X-Test"), QByteArrayLiteral("yes"));
    if (HttpClient::serializeRequest(rawPacket)
        != QByteArrayLiteral("POST /path?item=one HTTP/1.1\r\nX-Test: yes\r\n"
                              "Host: example.invalid\r\nContent-Length: 4\r\n\r\nbody"))
        return 85;

    HttpResponse fixedLengthResponse;
    HttpResponseParser fixedLengthParser(fixedLengthResponse, QDateTime::currentMSecsSinceEpoch());
    if (!fixedLengthParser.feed(QByteArrayLiteral("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                                                  "X-Test: yes\r\n\r\nHello"))
        || fixedLengthResponse.statusCode != 200
        || fixedLengthResponse.bodyMode != HttpResponse::ContentLength
        || fixedLengthResponse.bodyLength != 5 || fixedLengthResponse.headerRanges.size() != 2)
        return 86;

    HttpResponse chunkedResponse;
    HttpResponseParser chunkedParser(chunkedResponse, QDateTime::currentMSecsSinceEpoch());
    if (!chunkedParser.feed(QByteArrayLiteral("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                              "3\r\nabc\r\n0\r\n"))
        || chunkedResponse.bodyMode != HttpResponse::Chunked
        || chunkedResponse.chunkRanges.size() != 1
        || chunkedResponse.chunkRanges.first().offset != chunkedResponse.bodyOffset + 3
        || chunkedResponse.chunkRanges.first().length != 3)
        return 87;

    ThreadSafeCookieJar cookieJar;
    QNetworkCookie nullDomainCookie(QByteArrayLiteral("global"), QByteArrayLiteral("one"));
    QNetworkCookie otherDomainCookie(QByteArrayLiteral("other"), QByteArrayLiteral("two"));
    otherDomainCookie.setDomain(QStringLiteral("other.invalid"));
    if (!nullDomainCookie.domain().isNull() || !cookieJar.insertCookie(nullDomainCookie)
        || !cookieJar.insertCookie(otherDomainCookie)
        || !cookieJar.cookiesForUrl(QUrl(QStringLiteral("https://example.invalid/")))
                .contains(nullDomainCookie)
        || cookieJar.cookiesForUrl(QUrl(QStringLiteral("https://example.invalid/")))
                .contains(otherDomainCookie)
        || !cookieJar.deleteCookie(nullDomainCookie))
        return 84;

    const QUrl crawlerPage(QStringLiteral("https://example.invalid/dir/page.html"));
    const QString crawlerDocument = QStringLiteral(
        "<base href='/assets/'><a href='one.html'><a HREF=two.html>"
        "<a href='mailto:skip@example.invalid'><script><a href='script.html'>"
        "<img src='script.js'></script><img SRC=icon.svg>"
        "<iframe src='frame.html'></iframe>");
    if (crawlerHtmlHrefLocations(crawlerPage, crawlerDocument)
        != QList<QUrl>{QUrl(QStringLiteral("https://example.invalid/assets/")),
                        QUrl(QStringLiteral("https://example.invalid/assets/one.html")),
                        QUrl(QStringLiteral("https://example.invalid/assets/two.html"))})
        return 63;
    if (crawlerHtmlSourceLocations(crawlerPage, crawlerDocument)
        != QList<QUrl>{QUrl(QStringLiteral("https://example.invalid/assets/icon.svg")),
                        QUrl(QStringLiteral("https://example.invalid/assets/frame.html"))})
        return 65;
    if (crawlerHtmlIframeLocations(crawlerPage, crawlerDocument)
        != QList<QUrl>{QUrl(QStringLiteral("https://example.invalid/assets/frame.html"))})
        return 66;
    if (crawlerScriptExpression().pattern() != QStringLiteral("<script[\\s\\S]+?</script>")
        || crawlerIframeExpression().patternOptions() != QRegularExpression::CaseInsensitiveOption)
        return 67;

    if (crawlerMetaRefreshLocations(
            crawlerPage,
            QStringLiteral("<base href='/redirects/'><meta http-equiv=refresh url=next.html>"
                           "<meta http-equiv=refresh url=ignored.html>"))
            != QList<QUrl>{QUrl(QStringLiteral("https://example.invalid/redirects/next.html"))}
        || crawlerMetaRefreshExpression().pattern()
            != QStringLiteral("<META\\s+[^>]*HTTP-EQUIV\\s*=\\s*['|\"]*REFRESH['|\"]*\\s+[^>]*URL\\s*=\\s*[\"|']*([^>\\s'\"]+)"))
        return 64;

    // gui.exe:0x14006E3D4-0x14006E5D4 distinguishes an absent header from an
    // empty one, and does not parse JavaScript content as a crawler document.
    if (!crawlerAcceptsContentType(QByteArray())
        || crawlerAcceptsContentType(QByteArrayLiteral(""))
        || !crawlerAcceptsContentType(QByteArrayLiteral("TEXT/HTML; charset=utf-8"))
        || crawlerAcceptsContentType(QByteArrayLiteral("text/javascript"))
        || crawlerAcceptsContentType(QByteArrayLiteral("application/xml")))
        return 73;

    const auto crawlerRequest = makeCrawlerRequest(
        QUrl(QStringLiteral("https://example.invalid/assets/next.html?item=1")),
        crawlerPage, 7, 2);
    if (!crawlerRequest || crawlerRequest->target
        != QStringLiteral("https://example.invalid/assets/next.html?item=1"))
        return 68;
    if (crawlerRequest->field20 != 1 || !crawlerRequest->field28.isEmpty()
        || crawlerRequest->field6C != 8 || crawlerRequest->field60 != 2
        || crawlerRequest->field68 != 0 || crawlerRequest->field88 != 2)
        return 70;
    if (crawlerRequest->headers.value(QByteArrayLiteral("referer"))
        != HttpRequestItem::HeaderValues{{QByteArrayLiteral("Referer"),
                                          QByteArrayLiteral("https://example.invalid/dir/page.html")}})
        return 71;

    const auto crawlerOverrideRequest = makeCrawlerRequest(
        QUrl(QStringLiteral("https://example.invalid/plain.html")), crawlerPage, 3, 1, 6, 44);
    if (!crawlerOverrideRequest || crawlerOverrideRequest->field6C != 4
        || crawlerOverrideRequest->field60 != 44 || crawlerOverrideRequest->field68 != 6
        || crawlerOverrideRequest->field88 != 0)
        return 69;

    const QList<QUrl> xmlSitemapLocations = crawlerXmlSitemapLocations(
        QUrl(QStringLiteral("https://example.invalid/dir/sitemap.xml")),
        QStringLiteral("application/xml"),
        QStringLiteral("<LOC>one.xml</LOC><loc><![CDATA[../two&amp;three.xml]]></loc>"
                       "<loc>javascript:skip</loc><loc>web.conf</loc>"));
    if (crawlerXmlSitemapLocationExpression().pattern()
            != QStringLiteral("<loc>(?:<!\\[CDATA\\[)?([\\s\\S]+?)(?:\\]\\]>)?<\\/loc>")
        || crawlerXmlSitemapLocationExpression().patternOptions()
            != QRegularExpression::CaseInsensitiveOption
        || xmlSitemapLocations
            != QList<QUrl>{QUrl(QStringLiteral("https://example.invalid/dir/one.xml")),
                            QUrl(QStringLiteral("https://example.invalid/two&three.xml"))}
        || !crawlerXmlSitemapLocations(
                 QUrl(QStringLiteral("https://example.invalid/dir/sitemap.xml")),
                 QStringLiteral("application/XML"), QStringLiteral("<loc>one.xml</loc>"))
                 .isEmpty()
        || crawlerAcceptsResolvedLocation(QUrl(QStringLiteral("mailto:test@example.invalid"))))
        return 61;

    const QUrl robotsUrl(QStringLiteral("https://example.invalid/dir/robots.txt"));
    const QSet<QUrl> robotResources = robotTxtResourceLocations(
        robotsUrl,
        QStringLiteral("Disallow: /private\nAllow: /public\nNoIndex: /hidden&amp;value\n"
                       "Disallow: /wild*\nAllow: /suffix$\nDisallow: /private\n"));
    if (robotTxtResourceExpression().pattern()
            != QStringLiteral("(?:noindex|(?:dis)?allow)\\s*:\\s*([^:]+?)$")
        || robotTxtResourceExpression().patternOptions()
            != (QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption)
        || robotResources.size() != 3
        || !robotResources.contains(QUrl(QStringLiteral("https://example.invalid/private")))
        || !robotResources.contains(QUrl(QStringLiteral("https://example.invalid/public")))
        || !robotResources.contains(QUrl(QStringLiteral("https://example.invalid/hidden&value"))))
        return 59;

    const QList<QUrl> robotSitemaps = robotTxtSitemapLocations(
        robotsUrl,
        QStringLiteral("sItEmAp: ../one.xml\nSitemap : /two&amp;three.xml\n"
                       "Sitemap: /skip*\nSitemap: /skip$\n"));
    if (robotTxtSitemapExpression().pattern()
            != QStringLiteral("Sitemap\\s*:\\s*([^\\n]+?)$")
        || robotTxtSitemapExpression().patternOptions()
            != (QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption)
        || robotSitemaps
            != QList<QUrl>{QUrl(QStringLiteral("https://example.invalid/one.xml")),
                           QUrl(QStringLiteral("https://example.invalid/two&three.xml"))})
        return 60;

    if (decodeNumericHtmlCharacterReferences(QStringLiteral("left&#65;&#x42; &amp; right"))
            != QStringLiteral("leftAB &amp; right"))
        return 49;

    if (decodeHtmlCharacterReferences(QStringLiteral("&AMP;&apos;&doesNotExist; &#x42;"))
            != QStringLiteral("&'&doesNotExist; B"))
        return 50;

    if (decodeHtmlCharacterReferences(QStringLiteral("&Aacute;&aring;"))
            != QString::fromUtf8("Áå"))
        return 51;

    if (decodeHtmlCharacterReferences(QStringLiteral("&Atilde;&ccedil;&Ecirc;"))
            != QString::fromUtf8("ÃçÊ"))
        return 52;

    if (decodeHtmlCharacterReferences(QStringLiteral("&ETH;&euml;&Iuml;"))
            != QString::fromUtf8("ÐëÏ"))
        return 53;

    if (decodeHtmlCharacterReferences(QStringLiteral("&Ntilde;&oslash;&Ouml;"))
            != QString::fromUtf8("ÑøÖ"))
        return 54;

    if (decodeHtmlCharacterReferences(QStringLiteral("&THORN;&uuml;&Yacute;"))
            != QString::fromUtf8("ÞüÝ"))
        return 55;

    if (decodeHtmlCharacterReferences(QStringLiteral("&para;")) != QString(QChar(0x00B6)))
        return 56;

    if (decodeHtmlCharacterReferences(QStringLiteral("&COPY;&CenterDot;&DiacriticalAcute;"))
            != QString(QChar(0x00A9)) + QChar(0x00B7) + QChar(0x00B4))
        return 57;

    QByteArray smspEnvelope;
    QBuffer smspWriteDevice(&smspEnvelope);
    smspWriteDevice.open(QIODevice::WriteOnly);
    QDataStream smspWriter(&smspWriteDevice);
    writeSmspPreamble(smspWriter);
    smspWriter << quint32(0xAABBCCDD); // stand-in for unrecovered payload
    writeSmspTerminalMarker(smspWriter);
    QBuffer smspReadDevice(&smspEnvelope);
    smspReadDevice.open(QIODevice::ReadOnly);
    QDataStream smspReader(&smspReadDevice);
    quint32 placeholderPayload = 0;
    if (readSmspPreamble(smspReader) != SmspEnvelopeStatus::Ok)
        return 47;
    smspReader >> placeholderPayload;
    if (placeholderPayload != 0xAABBCCDD || readSmspTerminalMarker(smspReader) != SmspEnvelopeStatus::Ok)
        return 48;

    // gui.exe:0x1400E1D30/0x1400E1D36 distinguishes an older format from a
    // future format before consuming the edition or component payload.
    QByteArray olderSmsp;
    QBuffer olderDevice(&olderSmsp);
    olderDevice.open(QIODevice::WriteOnly);
    QDataStream olderWriter(&olderDevice);
    olderWriter << QByteArrayLiteral("SmartScanner") << quint32(299);
    olderDevice.close();
    olderDevice.open(QIODevice::ReadOnly);
    QDataStream olderReader(&olderDevice);
    if (readSmspPreamble(olderReader) != SmspEnvelopeStatus::CorruptedData)
        return 74;

    QByteArray newerSmsp;
    QBuffer newerDevice(&newerSmsp);
    newerDevice.open(QIODevice::WriteOnly);
    QDataStream newerWriter(&newerDevice);
    newerWriter << QByteArrayLiteral("SmartScanner") << quint32(301);
    newerDevice.close();
    newerDevice.open(QIODevice::ReadOnly);
    QDataStream newerReader(&newerDevice);
    if (readSmspPreamble(newerReader) != SmspEnvelopeStatus::UnsupportedVersion)
        return 75;

    const auto directoryRootItem = makeDirectoryRootRequest(
        QStringLiteral("https://example.invalid/assets/"),
        QUrl(QStringLiteral("https://example.invalid/landing page")), 12345);
    const auto directoryReferer = directoryRootItem->headers.value(QByteArrayLiteral("referer"));
    if (!directoryRootItem || directoryRootItem->target != QStringLiteral("https://example.invalid/assets/")
        || directoryRootItem->field20 != 1 || directoryRootItem->field60 != 12345
        || directoryRootItem->field68 != 489 || directoryRootItem->field88 != 2
        || directoryReferer.size() != 1
        || directoryReferer.first().second != QByteArrayLiteral("https://example.invalid/landing page"))
        return 43;

    const auto indexItem = makeIndexSeedRequest(
        QStringLiteral("https://example.invalid/index-target"),
        QUrl(QStringLiteral("https://example.invalid/referer")), 56789);
    const auto indexReferer = indexItem->headers.value(QByteArrayLiteral("referer"));
    if (!indexItem || indexItem->field20 != 1 || indexItem->field50 != 6
        || indexItem->field60 != 56789 || indexItem->field6C != 1
        || indexItem->field68 != 489 || indexItem->field70 != QStringLiteral("?!index!?")
        || indexReferer.size() != 1
        || indexReferer.first().second != QByteArrayLiteral("https://example.invalid/referer"))
        return 44;

    virtualReader.readFromStream(urlItemReader);
    if (urlItemWriter.status() != QDataStream::Ok || urlItemReader.status() != QDataStream::Ok
        || decodedUrlItem.target != originalUrlItem.target
        || decodedUrlItem.headers != originalUrlItem.headers
        || decodedUrlItem.field58 != originalUrlItem.field58
        || decodedUrlItem.field60 != originalUrlItem.field60
        || decodedUrlItem.field68 != originalUrlItem.field68
        || decodedUrlItem.field6C != 0
        || decodedUrlItem.field70 != originalUrlItem.field70
        || decodedUrlItem.field88 != originalUrlItem.field88
        || decodedUrlItem.field8C != originalUrlItem.field8C
        || decodedUrlItem.field90 != originalUrlItem.field90
        || decodedUrlItem.field94 != originalUrlItem.field94)
        return 12;

    HttpRequestRawPacket originalPacket;
    originalPacket.target = QStringLiteral("https://example.invalid/raw");
    originalPacket.field20 = 9;
    originalPacket.field28 = QByteArrayLiteral("query=value");
    originalPacket.setHeader(QByteArrayLiteral("Content-Type"), QByteArrayLiteral("text/plain"));
    originalPacket.field50 = 21;
    originalPacket.protocol = QByteArrayLiteral("HTTP/1.1");
    originalPacket.payload = QByteArrayLiteral("body");
    QByteArray packetBytes;
    QBuffer packetWriterDevice(&packetBytes);
    packetWriterDevice.open(QIODevice::WriteOnly);
    QDataStream packetWriter(&packetWriterDevice);
    packetWriter.setVersion(QDataStream::Qt_6_7);
    HttpRequestItem &packetVirtualWriter = originalPacket;
    packetVirtualWriter.writeToStream(packetWriter);
    HttpRequestRawPacket decodedPacket;
    QBuffer packetReaderDevice(&packetBytes);
    packetReaderDevice.open(QIODevice::ReadOnly);
    QDataStream packetReader(&packetReaderDevice);
    packetReader.setVersion(QDataStream::Qt_6_7);
    HttpRequestItem &packetVirtualReader = decodedPacket;
    packetVirtualReader.readFromStream(packetReader);
    if (packetVirtualWriter.streamTypeName() != QStringLiteral("HttpRequestRawPacket")
        || packetWriter.status() != QDataStream::Ok || packetReader.status() != QDataStream::Ok
        || decodedPacket.target != originalPacket.target
        || decodedPacket.field28 != originalPacket.field28
        || decodedPacket.headers != originalPacket.headers
        || decodedPacket.field50 != originalPacket.field50
        || decodedPacket.payload != originalPacket.payload
        || !decodedPacket.protocol.isEmpty())
        return 13;

    HtmlForm originalForm;
    originalForm.target = QStringLiteral("https://example.invalid/form");
    HtmlFormInput formInput;
    formInput.field00 = QStringLiteral("name");
    formInput.field18 = QStringLiteral("Alice Smith");
    formInput.field30 = QStringLiteral("text");
    formInput.field48 = {QStringLiteral("first")};
    formInput.field60 = {QStringLiteral("second")};
    formInput.field78 = true;
    formInput.field80 = QStringLiteral("profile-name");
    formInput.field98.insert(QStringLiteral("choice"), QStringLiteral("one"));
    originalForm.field98.append(formInput);
    HtmlFormValueRule formRule;
    formRule.field00 = QRegularExpression(QStringLiteral(".*"));
    formRule.field08 = QRegularExpression(QStringLiteral(".*"));
    formRule.field10 = QRegularExpression(QStringLiteral(".*"));
    formRule.field18 = QRegularExpression(QStringLiteral(".*"));
    formRule.field20 = QStringLiteral("replacement");
    auto sharedRules = QSharedPointer<QList<HtmlFormValueRule>>::create();
    sharedRules->append(formRule);
    originalForm.setExtensionFrom(&sharedRules);

    QByteArray formBytes;
    QBuffer formWriterDevice(&formBytes);
    formWriterDevice.open(QIODevice::WriteOnly);
    QDataStream formWriter(&formWriterDevice);
    formWriter.setVersion(QDataStream::Qt_6_7);
    HttpRequestItem &formVirtualWriter = originalForm;
    formVirtualWriter.writeToStream(formWriter);
    HtmlForm decodedForm;
    QBuffer formReaderDevice(&formBytes);
    formReaderDevice.open(QIODevice::ReadOnly);
    QDataStream formReader(&formReaderDevice);
    formReader.setVersion(QDataStream::Qt_6_7);
    HttpRequestItem &formVirtualReader = decodedForm;
    formVirtualReader.readFromStream(formReader);
    if (formVirtualWriter.streamTypeName() != QStringLiteral("HtmlForm")
        || formWriter.status() != QDataStream::Ok || formReader.status() != QDataStream::Ok)
        return 14;
    if (decodedForm.target != originalForm.target || decodedForm.field98.size() != 1)
        return 15;
    const HtmlFormInput &decodedInput = decodedForm.field98.first();
    if (decodedInput.field00 != formInput.field00 || decodedInput.field18 != formInput.field18
        || decodedInput.field30 != formInput.field30 || decodedInput.field48 != formInput.field48
        || decodedInput.field60 != formInput.field60 || decodedInput.field78 != formInput.field78
        || decodedInput.field80 != formInput.field80 || decodedInput.field98 != formInput.field98)
        return 16;
    if (decodedForm.fieldB0 || originalForm.fieldB0 != sharedRules)
        return 17;
    if (originalForm.field28Copy() != QByteArrayLiteral("name=Alice%20Smith"))
        return 18;

    originalForm.field20 = 1;
    if (originalForm.url().query(QUrl::FullyEncoded) != QStringLiteral("name=Alice%20Smith"))
        return 19;
    originalForm.target = QStringLiteral("https://example.invalid");
    if (originalForm.url().path() != QStringLiteral("/"))
        return 20;

    auto streamUrlItem = QSharedPointer<urlItem>::create();
    streamUrlItem->target = QStringLiteral("https://example.invalid/one");
    auto streamForm = QSharedPointer<HtmlForm>::create();
    streamForm->target = QStringLiteral("https://example.invalid/two");
    streamForm->field98.append(formInput);
    const QList<RequestItemPointer> originalItems = {streamUrlItem, streamForm};
    QByteArray itemBytes;
    QBuffer itemWriterDevice(&itemBytes);
    itemWriterDevice.open(QIODevice::WriteOnly);
    QDataStream itemWriter(&itemWriterDevice);
    itemWriter.setVersion(QDataStream::Qt_6_7);
    writeRequestItems(itemWriter, originalItems);
    QList<RequestItemPointer> decodedItems;
    QBuffer itemReaderDevice(&itemBytes);
    itemReaderDevice.open(QIODevice::ReadOnly);
    QDataStream itemReader(&itemReaderDevice);
    itemReader.setVersion(QDataStream::Qt_6_7);
    readRequestItems(itemReader, decodedItems);
    if (itemWriter.status() != QDataStream::Ok || itemReader.status() != QDataStream::Ok
        || decodedItems.size() != 2
        || decodedItems.at(0)->streamTypeName() != QStringLiteral("urlItem")
        || decodedItems.at(1)->streamTypeName() != QStringLiteral("HtmlForm"))
        return 21;

    QByteArray unknownItemBytes;
    QBuffer unknownWriterDevice(&unknownItemBytes);
    unknownWriterDevice.open(QIODevice::WriteOnly);
    QDataStream unknownWriter(&unknownWriterDevice);
    unknownWriter << QStringLiteral("unrecognized");
    QBuffer unknownReaderDevice(&unknownItemBytes);
    unknownReaderDevice.open(QIODevice::ReadOnly);
    QDataStream unknownReader(&unknownReaderDevice);
    RequestItemPointer unknownItem;
    readRequestItem(unknownReader, unknownItem);
    if (unknownReader.status() != QDataStream::ReadCorruptData || unknownItem)
        return 22;

    urlItem identityA;
    identityA.target = QStringLiteral("HTTPS://WWW.Example.invalid:443/index.html?z=1&a=2");
    identityA.field20 = 3;
    identityA.field28 = QByteArrayLiteral("body");
    identityA.field50 = 15;
    identityA.headers[QByteArrayLiteral("accept")].append(
        qMakePair(QByteArrayLiteral("Accept"), QByteArrayLiteral("one")));
    identityA.headers[QByteArrayLiteral("referer")].append(
        qMakePair(QByteArrayLiteral("Referer"), QByteArrayLiteral("https://first.invalid")));
    urlItem identityB = identityA;
    identityB.headers[QByteArrayLiteral("accept")][0].second = QByteArrayLiteral("two");
    identityB.headers[QByteArrayLiteral("referer")][0].second = QByteArrayLiteral("https://second.invalid");
    urlItem identityC = identityA;
    identityC.headers[QByteArrayLiteral("cookie")].append(
        qMakePair(QByteArrayLiteral("Cookie"), QByteArrayLiteral("changed")));
    if (requestItemIdentity(identityA) != requestItemIdentity(identityB)
        || requestItemIdentity(identityA) == requestItemIdentity(identityC))
        return 25;

    FileListStreamState originalFileList;
    originalFileList.field18.insert(1);
    originalFileList.field34 = 7;
    originalFileList.field50.insert(2, 3);
    originalFileList.field58 = {4, 5};
    originalFileList.field70.insert(6);
    originalFileList.field90 = 7000;
    originalFileList.fieldB0.field08 = 8;
    originalFileList.fieldB0.field0C = 9;
    originalFileList.fieldB0.field10 = 10;
    originalFileList.fieldB0.field18.insert(11, 12);
    originalFileList.fieldB0.field20.insert(13, {14, 15});
    originalFileList.fieldD8.field20.insert(16, {17});
    originalFileList.field118 = 18;
    originalFileList.field134 = 19;
    originalFileList.field78 = originalItems;
    QByteArray fileListBytes;
    QBuffer fileListWriterDevice(&fileListBytes);
    fileListWriterDevice.open(QIODevice::WriteOnly);
    QDataStream fileListWriter(&fileListWriterDevice);
    fileListWriter.setVersion(QDataStream::Qt_6_7);
    fileListWriter << originalFileList;
    FileListStreamState decodedFileList;
    QBuffer fileListReaderDevice(&fileListBytes);
    fileListReaderDevice.open(QIODevice::ReadOnly);
    QDataStream fileListReader(&fileListReaderDevice);
    fileListReader.setVersion(QDataStream::Qt_6_7);
    fileListReader >> decodedFileList;
    if (fileListWriter.status() != QDataStream::Ok || fileListReader.status() != QDataStream::Ok
        || decodedFileList.field18 != originalFileList.field18
        || decodedFileList.field34 != originalFileList.field34
        || decodedFileList.field50 != originalFileList.field50
        || decodedFileList.field58 != originalFileList.field58
        || decodedFileList.field70 != originalFileList.field70
        || decodedFileList.field90 != originalFileList.field90
        || decodedFileList.fieldB0.field18 != originalFileList.fieldB0.field18
        || decodedFileList.fieldB0.field20 != originalFileList.fieldB0.field20
        || decodedFileList.fieldD8.field20 != originalFileList.fieldD8.field20
        || decodedFileList.field118 != originalFileList.field118
        || decodedFileList.field134 != originalFileList.field134
        || decodedFileList.field78.size() != 2
        || decodedFileList.field78.at(1)->streamTypeName() != QStringLiteral("HtmlForm"))
        return 23;

    FileCountConstrain directoryConstraint;
    directoryConstraint.field08 = 1;
    const QUrl firstDirectoryItem(QStringLiteral("https://example.invalid/a/one"));
    const QUrl secondDirectoryItem(QStringLiteral("https://example.invalid/a/two"));
    if (!directoryConstraint.acceptAndRecord(firstDirectoryItem)
        || !directoryConstraint.acceptAndRecord(firstDirectoryItem)
        || directoryConstraint.acceptAndRecord(secondDirectoryItem)
        || !directoryConstraint.contains(firstDirectoryItem)
        || directoryConstraint.contains(secondDirectoryItem))
        return 26;

    DirCountConstrain directoryOnlyConstraint;
    if (!directoryOnlyConstraint.acceptAndRecord(firstDirectoryItem)
        || directoryOnlyConstraint.acceptAndRecord(secondDirectoryItem))
        return 27;

    FileList recoveredFileList;
    if (recoveredFileList.size() != 0
        || recoveredFileList.find([](const RequestItemPointer &) { return true; }))
        return 28;

    recoveredFileList.field20 = QRegularExpression(QStringLiteral(".*"));
    auto queuedItem = QSharedPointer<urlItem>::create();
    queuedItem->target = QStringLiteral("https://example.invalid/queued");
    if (recoveredFileList.add(queuedItem, 0x1c) != 1 || queuedItem->field58 != 1
        || recoveredFileList.size() != 1 || recoveredFileList.add(queuedItem, 0x1c) != 0)
        return 35;

    FileList limitFileList;
    limitFileList.field28 = 1;
    auto limitFirst = QSharedPointer<urlItem>::create();
    limitFirst->target = QStringLiteral("https://example.invalid/first");
    auto limitSecond = QSharedPointer<urlItem>::create();
    limitSecond->target = QStringLiteral("https://example.invalid/second");
    const QVariantMap skippedSummary = limitFileList.skippedSummary();
    if (limitFileList.add(limitFirst, 0x01) != 1 || limitFileList.add(limitSecond, 0x01) != 0
        || skippedSummary.value(QStringLiteral("total")).toUInt() != 0
        || limitFileList.skippedSummary().value(QStringLiteral("total")).toUInt() != 1
        || limitFileList.skippedSummary().value(QStringLiteral("reasons")).toMap()
               .value(QStringLiteral("URL limit reached")).toUInt() != 1)
        return 84;

    Scanner recoveredScanner;
    if (recoveredScanner.fileList().size() != 0)
        return 29;

    recoveredScanner.start();
    if (recoveredScanner.status() != Scanner::Scanning)
        return 37;
    recoveredScanner.pause();
    if (recoveredScanner.status() != Scanner::Pausing)
        return 38;
    recoveredScanner.resume();
    if (recoveredScanner.status() != Scanner::Scanning)
        return 39;
    recoveredScanner.stop();
    application.processEvents();
    if (recoveredScanner.status() != Scanner::Stopped)
        return 40;

    bool extensionlessFileName = false;
    if (!fileListUrlHeuristic(QUrl(QStringLiteral("https://example.invalid/articles")),
                              &extensionlessFileName)
        || !extensionlessFileName
        || fileListUrlHeuristic(QUrl(QStringLiteral("https://example.invalid/index.php")))
        || !fileListUrlHeuristic(QUrl(QStringLiteral("https://example.invalid/tag/one"))))
        return 30;

    const QUrl queryNameUrl(QStringLiteral("https://example.invalid/?page=1"));
    const QList<QPair<QString, QString>> packetQueryItems{{QStringLiteral("token"),
                                                            QStringLiteral("abc")}};
    QSet<quint64> seenQueryNames;
    if (!fileListHasUnseenQueryName(seenQueryNames, queryNameUrl, packetQueryItems))
        return 31;
    seenQueryNames.insert(qHash(QStringView(QStringLiteral("page?example.invalid")), 1001));
    seenQueryNames.insert(qHash(QStringView(QStringLiteral("token?example.invalid^")), 1001));
    if (fileListHasUnseenQueryName(seenQueryNames, queryNameUrl, packetQueryItems))
        return 32;

    if (!fileListRetainsQueryItemForRateLimit(
            {QStringLiteral("module"), QStringLiteral("123456789012")})
        || !fileListRetainsQueryItemForRateLimit(
            {QStringLiteral("name"), QStringLiteral("short-text")})
        || fileListRetainsQueryItemForRateLimit(
            {QStringLiteral("name"), QStringLiteral("123456")})
        || fileListRetainsQueryItemForRateLimit(
            {QStringLiteral("name"), QStringLiteral("eleven_chars")}))
        return 33;

    FileListQueryState queryRateState;
    if (!queryRateState.accept(queryNameUrl, packetQueryItems)
        || queryRateState.accept(queryNameUrl, packetQueryItems)
        || queryRateState.seenNames() != seenQueryNames)
        return 34;

    return 0;
}
