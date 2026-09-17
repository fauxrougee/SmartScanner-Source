#include "duration.h"
#include "filelist.h"
#include "fileliststream.h"
#include "issuedb.h"
#include "issuedbstream.h"
#include "networkmanager.h"
#include "requestmanager.h"
#include "scanconfig.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QIODevice>
#include <QStandardPaths>
#include <QTime>
#include <QJsonArray>

// Independent native-layout fixtures. Prepared for the next batched build;
// this test does not make HTTP requests or start a scan.
template<class T> QByteArray encoded(const T &value)
{
    QByteArray bytes;
    QDataStream stream(&bytes, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_7);
    stream << value;
    return bytes;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("ReconstructionTests"));
    QCoreApplication::setApplicationName(QStringLiteral("NativeComponentBatch"));
    QStandardPaths::setTestModeEnabled(true);

    // Native Duration stream imports are qint64, QTime, QDate. Midnight
    // must not become the null-time sentinel; stream loading starts no timer.
    for (const QTime time : {QTime(), QTime(0, 0), QTime(13, 24, 35, 678)}) {
        QByteArray fixture;
        QDataStream out(&fixture, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_6_7);
        out << qint64(3661) << time << QDate(2026, 9, 16);
        Duration duration;
        QDataStream in(fixture);
        in.setVersion(QDataStream::Qt_6_7);
        in >> duration;
        if (in.status() != QDataStream::Ok || duration.elapsedSeconds() != 3661
            || duration.startTimeMilliseconds() != (time.isNull() ? -1 : time.msecsSinceStartOfDay())
            || encoded(duration) != fixture)
            return 1;
    }

    IssueDbStreamState issueState;
    Issue issue;
    issue.field30 = QUrl(QStringLiteral("https://example.invalid/issue"));
    issueState.field2A0.append(issue);
    issueState.field2B8.insert(12345, issue);
    issueState.field2C0 = 98765;
    issueState.field2C8.insert(QUrl(QStringLiteral("https://example.invalid/seen")));
    const QByteArray issueBytes = encoded(issueState);
    IssueDb db;
    int added = 0;
    QObject::connect(&db, &IssueDb::newIssueAdded, &app, [&](Issue) { ++added; });
    QDataStream issueReader(issueBytes);
    issueReader.setVersion(QDataStream::Qt_6_7);
    issueReader >> db;
    if (issueReader.status() != QDataStream::Ok || added != 0
        || db.issues().size() != 1 || db.pendingIssues().size() != 1
        || encoded(db) != issueBytes)
        return 2;

    FileListStreamState files;
    files.field18.insert(123);
    files.field34 = 75;
    files.field50.insert(19, 3);
    files.field58.append(19);
    files.field70.insert(21);
    files.field90 = 1;
    files.field118 = 2;
    files.field11C = 3;
    auto item = QSharedPointer<urlItem>::create();
    item->target = QStringLiteral("https://example.invalid/queued");
    item->field58 = 75;
    item->field8C = 3;
    item->field90 = 0;
    files.field78.append(item);
    const QByteArray fileBytes = encoded(files);
    FileList list;
    QDataStream fileReader(fileBytes);
    fileReader.setVersion(QDataStream::Qt_6_7);
    fileReader >> list;
    if (fileReader.status() != QDataStream::Ok || list.size() != 1
        || encoded(list) != fileBytes)
        return 3;

    // Native RequestItem list reader clears partially read lists and uses
    // SizeLimitExceeded for the null/negative count encoding.
    QByteArray partial;
    QDataStream partialWriter(&partial, QIODevice::WriteOnly);
    partialWriter.setVersion(QDataStream::Qt_6_7);
    partialWriter << quint32(2);
    writeRequestItem(partialWriter, item);
    QList<RequestItemPointer> items{item};
    QDataStream partialReader(partial);
    partialReader.setVersion(QDataStream::Qt_6_7);
    readRequestItems(partialReader, items);
    if (partialReader.status() == QDataStream::Ok || !items.isEmpty()) return 4;
    QByteArray invalidCount = QByteArray::fromHex("ffffffff");
    QDataStream invalidReader(invalidCount);
    invalidReader.setVersion(QDataStream::Qt_6_7);
    items.append(item);
    readRequestItems(invalidReader, items);
    if (invalidReader.status() != QDataStream::SizeLimitExceeded || !items.isEmpty()) return 5;

    QByteArray networkBytes;
    QDataStream networkWriter(&networkBytes, QIODevice::WriteOnly);
    networkWriter.setVersion(QDataStream::Qt_6_7);
    networkWriter << qint32(2) << quint32(3) << quint32(5)
                  << QUrl(QStringLiteral("https://example.invalid/last"))
                  << QDateTime(QDate(2026, 9, 16), QTime(1, 2, 3))
                  << qint64(2048) << QList<qint64>{7, 8};
    NetworkManager network(QStringLiteral("native-stream-batch"));
    const auto concurrent = network.concurrentLimit();
    QDataStream networkReader(networkBytes);
    networkReader.setVersion(QDataStream::Qt_6_7);
    networkReader >> network;
    if (networkReader.status() != QDataStream::Ok || network.activeRequests() != 3
        || network.totalRequests() != 5 || network.concurrentLimit() != concurrent
        || encoded(network) != networkBytes)
        return 6;

    RequestManager manager;
    QNetworkRequest request(QUrl(QStringLiteral("https://example.invalid/")));
    manager.prepareRequest(request);
    if (request.attribute(static_cast<QNetworkRequest::Attribute>(8)).metaType().id() != QMetaType::Int
        || request.attribute(static_cast<QNetworkRequest::Attribute>(8)).toInt() != 1
        || request.attribute(static_cast<QNetworkRequest::Attribute>(22)).metaType().id() != QMetaType::Int
        || request.attribute(static_cast<QNetworkRequest::Attribute>(22)).toInt() != 0
        || request.attribute(static_cast<QNetworkRequest::Attribute>(1001)).toLongLong() <= 0)
        return 7;
    QNetworkCookie cookie(QByteArrayLiteral("name"), QByteArrayLiteral("value"));
    cookie.setDomain(QStringLiteral("example.invalid"));
    cookie.setPath(QStringLiteral("/"));
    request.setHeader(QNetworkRequest::CookieHeader, QVariant::fromValue(QList<QNetworkCookie>{cookie}));
    QList<QNetworkCookie> saved, injected;
    manager.prepareCookies(request, saved, injected);
    if (!saved.isEmpty() || injected.size() != 1
        || request.attribute(static_cast<QNetworkRequest::Attribute>(1006)).toByteArray() != "name=value; ")
        return 8;
    manager.restoreCookies(saved, injected);
    QNetworkRequest after(request.url());
    saved.clear();
    injected.clear();
    manager.prepareCookies(after, saved, injected);
    if (!after.attribute(static_cast<QNetworkRequest::Attribute>(1006)).toByteArray().isEmpty())
        return 9;

    // Native literals prove radio is gated by checked, select uses first
    // option as fallback, and uppercase RADIO is not equal to lowercase radio.
    HtmlForm form;
    HtmlFormInput input;
    input.field00 = QStringLiteral("field");
    input.field18 = QStringLiteral("stored");
    input.field30 = QStringLiteral("radio");
    form.field98 = {input};
    if (!form.urlEncoded().isEmpty()) return 10;
    form.field98[0].field30 = QStringLiteral("RADIO");
    if (form.urlEncoded() != "field=stored") return 11;
    form.field98[0].field30 = QStringLiteral("select");
    form.field98[0].field18 = QString();
    form.field98[0].field48 = {QStringLiteral("first")};
    if (form.urlEncoded() != "field=first") return 12;
    auto rules = QSharedPointer<QList<HtmlFormValueRule>>::create();
    form.setExtensionFrom(&rules);
    if (form.fieldB0 != rules) return 13;
    form.field98[0].field30 = QString();
    form.field98[0].field18 = QStringLiteral("plain");
    if (form.urlEncoded() != "field=plain") return 14;

    // gui.exe config +40 owns a non-null shared list even without inputs.
    const ScanConfig defaults;
    if (!defaults.valueRules() || !defaults.valueRules()->isEmpty()) return 15;
    const QJsonObject inputsObject{{QStringLiteral("inputs"), QJsonArray{
        QStringLiteral("a;;b;;c"),                  // ignored: three fields
        QStringLiteral("a;;b;;c;;d"),               // null fifth field
        QStringLiteral("a;;b;;c;;d;;"),             // empty but non-null fifth
        QStringLiteral("name;;text;;near;;url;;value;;ignored")
    }}};
    const ScanConfig withRules = ScanConfig::fromJson(
        QJsonObject{{QStringLiteral("f"), inputsObject}});
    const auto configured = withRules.valueRules();
    if (!configured || configured->size() != 3
        || !configured->at(0).field20.isNull()
        || !configured->at(1).field20.isEmpty()
        || configured->at(1).field20.isNull()
        || configured->at(2).field20 != QStringLiteral("value")) return 16;
    const ScanConfig copied(withRules);
    if (copied.valueRules() != configured) return 17;
    if (!configured->at(2).field00.match(QStringLiteral("name")).hasMatch()
        || !configured->at(2).field08.match(QStringLiteral("text")).hasMatch()
        || !configured->at(2).field10.match(QStringLiteral("near")).hasMatch()
        || !configured->at(2).field18.match(QStringLiteral("url")).hasMatch()) return 18;
    // gui.exe:0x14011ED61 and 0x14011F002: vector defaults and column order.
    if (defaults.vectorFlags() != 31 || !defaults.parameterExclusions()
        || !defaults.parameterExclusions()->isEmpty()) return 19;
    if (ScanConfig::fromJson({}).vectorFlags() != 0) return 20;
    const QJsonObject vectorObject{
        {QStringLiteral("vectors"), QJsonArray{QStringLiteral("GET"),
            QStringLiteral("header"), QStringLiteral(" post ")}},
        {QStringLiteral("parameterExclusion"), QJsonArray{
            QStringLiteral("short;;get;;row"),
            QStringLiteral("url;;name;;PoSt;;value;;ignored")}}
    };
    const ScanConfig vectorConfig = ScanConfig::fromJson(
        QJsonObject{{QStringLiteral("vector"), vectorObject}});
    const auto exclusions = vectorConfig.parameterExclusions();
    if (vectorConfig.vectorFlags() != 9 || exclusions->size() != 1) return 21;
    const auto &exclusion = exclusions->first();
    if (exclusion.field18 != 2
        || !exclusion.field00.match(QStringLiteral("url")).hasMatch()
        || !exclusion.field08.match(QStringLiteral("name")).hasMatch()
        || !exclusion.field10.match(QStringLiteral("value")).hasMatch()) return 22;
    if (ScanConfig(vectorConfig).parameterExclusions() != exclusions) return 23;
    return 0;
}
