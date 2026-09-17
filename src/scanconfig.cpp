#include "scanconfig.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonValue>
#include <QRegularExpression>
#include <QTextStream>

#include <stdexcept>

namespace {

quint32 vectorTypeFlags(QString value)
{
    // gui.exe:0x140120840. Lowercase, no trimming.
    value = value.toLower();
    if (value == QStringLiteral("get")) return 1;
    if (value == QStringLiteral("post")) return 2;
    if (value == QStringLiteral("cookie")) return 4;
    if (value == QStringLiteral("header")) return 8;
    if (value == QStringLiteral("path")) return 16;
    if (value == QStringLiteral("any")) return 31;
    return 0;
}

qint32 requestKindForTargetMethod(const QString &method)
{
    // gui.exe:0x1400706A0 lowercases the input, then maps GET/POST/PUT/DELETE,
    // PATCH and HEAD to 1 through 6; every other spelling maps to zero.
    const QByteArray lowered = method.toUtf8().toLower();
    if (lowered == QByteArrayLiteral("get")) return 1;
    if (lowered == QByteArrayLiteral("post")) return 2;
    if (lowered == QByteArrayLiteral("put")) return 3;
    if (lowered == QByteArrayLiteral("delete")) return 4;
    if (lowered == QByteArrayLiteral("patch")) return 5;
    if (lowered == QByteArrayLiteral("head")) return 6;
    return 0;
}

void appendUrlItem(QList<QSharedPointer<urlItem>> &items, const QUrl &url)
{
    if (url.isValid())
        items.append(QSharedPointer<urlItem>::create(url.toString(), 1,
                                                      QByteArray()));
}

} // namespace

ScanConfig::ScanConfig() = default;

ScanConfig ScanConfig::fromJson(const QJsonObject &json) {
    ScanConfig config;
    config.m_json = json;

    // gui.exe:0x14011DC0D-0x14011DE09. The parser takes the array directly
    // from tests.scripts and appends every value in JSON order. cpuThreads is
    // first converted to QString, then base-10 int; only a positive value
    // replaces the constructor's -1 sentinel.
    const QJsonObject tests = json.value(QStringLiteral("tests")).toObject();
    for (const QJsonValue &script : tests.value(QStringLiteral("scripts")).toArray())
        config.m_testScripts.append(script.toString());
    const qint32 cpuThreads = tests.value(QStringLiteral("cpuThreads"))
                                    .toString().toInt(nullptr, 10);
    if (cpuThreads > 0)
        config.m_cpuThreads = cpuThreads;

    const QJsonObject crawler = json.value(QStringLiteral("crawler")).toObject();

    // gui.exe:0x14011DE85–0x14011E160. A manual scope compiles its regex
    // case-insensitively; every other scope type retains Qt's null regular
    // expression, whose empty pattern accepts any URL.
    // gui.exe:0x14011DE09-0x14011DE85. Parse scope flags.
    const QJsonObject scope = crawler.value(QStringLiteral("scope")).toObject();
    config.m_scanSubDomains = scope.value(QStringLiteral("scanSubDomains")).toBool(false);
    config.m_scanAbovePath = scope.value(QStringLiteral("scanAbovePath")).toBool(false);

    // gui.exe:0x14011DE85–0x14011E160. A manual scope compiles its regex
    // case-insensitively; every other scope type retains Qt's null regular
    // expression, whose empty pattern accepts any URL.
    if (scope.value(QStringLiteral("type")).toString().toLower()
        == QStringLiteral("manual")) {
        config.m_isManualScope = true;
        config.m_scopeExpression = QRegularExpression(
            scope.value(QStringLiteral("regex")).toString(),
            QRegularExpression::CaseInsensitiveOption);
        config.m_crawlStartDepth = scope.value(QStringLiteral("crawlStartDepth")).toInt(0);
    }

    // gui.exe:0x14011E160-0x14011E185. evaluteJsWithChromium (note typo in original).
    config.m_evaluateJsWithChromium = crawler.value(
        QStringLiteral("evaluteJsWithChromium")).toBool(false);

    // gui.exe:0x14011DBA0. The constructor at 0x14011CE00 initializes this
    // native field to -1.  The parser deliberately leaves it alone for a JSON
    // boolean (notably the distributed `"depth": false`); every other JSON
    // type is passed through QJsonValue::toVariant/QVariant::toInt.
    const QJsonValue depth = crawler.value(QStringLiteral("depth"));
    if (!depth.isBool())
        config.m_crawlerDepth = depth.toVariant().toInt();

    // gui.exe:0x14011E2A9–0x14011E353. Boolean count values are ignored;
    // all other JSON values are converted through QVariant::toULongLong.
    const QJsonValue count = crawler.value(QStringLiteral("count"));
    if (!count.isBool())
        config.m_crawlerCount = count.toVariant().toULongLong();

    // gui.exe:0x14011E365–0x14011E641. `fileExclusion` is a comma-separated
    // string. Empty fragments are skipped before each fragment is compiled
    // by gui.exe:0x1400831B0.
    const QJsonValue fileExclusion = crawler.value(QStringLiteral("fileExclusion"));
    if (!fileExclusion.isBool()) {
        const QStringList patterns = fileExclusion.toString().split(
            u',', Qt::SkipEmptyParts, Qt::CaseSensitive);
        for (const QString &pattern : patterns)
            config.m_fileExclusions.append(globExpression(pattern));
    }

    // gui.exe:0x14011E64D–0x14011E875. `urlExclusion` is an array whose
    // entries are compiled through the same glob helper.
    for (const QJsonValue &value : crawler.value(QStringLiteral("urlExclusion")).toArray())
        config.m_urlExclusions.append(globExpression(value.toString()));

    // gui.exe:0x14011E889-0x14011EC71. "f.inputs", four required fields,
    // optional fifth value. 0x140122600 returns a null QString out of range.
    const QJsonArray inputs = json.value(QStringLiteral("f")).toObject()
                                 .value(QStringLiteral("inputs")).toArray();
    for (const QJsonValue &input : inputs) {
        const QStringList fields = input.toString().split(
            QStringLiteral(";;"), Qt::KeepEmptyParts, Qt::CaseSensitive);
        if (fields.size() < 4)
            continue;
        HtmlFormValueRule rule;
        rule.field00 = globExpression(fields.at(0));
        rule.field08 = globExpression(fields.at(1));
        rule.field10 = globExpression(fields.at(2));
        rule.field18 = globExpression(fields.at(3));
        rule.field20 = fields.value(4);
        config.m_valueRules->append(rule);
    }

    // gui.exe:0x14011ED61-0x14011EE09: reset then accumulate vector masks.
    const QJsonObject vector = json.value(QStringLiteral("vector")).toObject();
    config.m_vectorFlags = 0;
    for (const QJsonValue &value : vector.value(QStringLiteral("vectors")).toArray())
        config.m_vectorFlags |= vectorTypeFlags(value.toString());

    // gui.exe:0x14011EFEA-0x14011F104: fields 0,1,3 are regexes; field 2 is
    // the mask. Keep empty split fields, ignore entries with fewer than four.
    for (const QJsonValue &value : vector.value(QStringLiteral("parameterExclusion")).toArray()) {
        const QStringList fields = value.toString().split(
            QStringLiteral(";;"), Qt::KeepEmptyParts, Qt::CaseSensitive);
        if (fields.size() < 4)
            continue;
        ParameterExclusionRule rule;
        rule.field00 = globExpression(fields.at(0));
        rule.field18 = static_cast<qint32>(vectorTypeFlags(fields.at(2)));
        rule.field10 = globExpression(fields.at(3));
        rule.field08 = globExpression(fields.at(1));
        config.m_parameterExclusions->append(rule);
    }

    // gui.exe:0x14011F1EA-0x14011F2A2. The conversion is unconditional,
    // including when the `http` object or its key is absent.
    config.m_maxParallelRequests = json.value(QStringLiteral("http")).toObject()
                                       .value(QStringLiteral("maxParallelRequests"))
                                       .toVariant().toUInt();

    const QJsonObject http = json.value(QStringLiteral("http")).toObject();
    // gui.exe:0x14011F2B3-0x14011F41E. The stored timeout is the signed
    // QVariant conversion, while the user agent keeps QJsonValue::toString's
    // null-vs-empty QString distinction.
    config.m_httpTimeout = http.value(QStringLiteral("timeout")).toVariant().toInt();
    config.m_userAgent = http.value(QStringLiteral("userAgent")).toString();

    // gui.exe:0x14011F597-0x14011F82E walks `http.headers` in JSON order,
    // converts value then name to UTF-8, and appends the resulting pair.
    for (const QJsonValue &headerValue : http.value(QStringLiteral("headers")).toArray()) {
        const QJsonObject header = headerValue.toObject();
        config.m_httpHeaders.append(qMakePair(
            header.value(QStringLiteral("name")).toString().toUtf8(),
            header.value(QStringLiteral("value")).toString().toUtf8()));
    }

    // gui.exe:0x14011F847-0x14011FC92. Each proxy member is independently
    // read from the ROOT `proxy` object (v95 = root QJsonObject, see
    // 0x14011F1FA; sms.exe:0x14011D9D0 identical). This deliberately
    // overwrites the constructor's noproxy/port-one defaults.
    const QJsonObject proxy = json.value(QStringLiteral("proxy")).toObject();
    config.m_proxyType = proxy.value(QStringLiteral("type")).toString();
    config.m_proxyHost = proxy.value(QStringLiteral("host")).toString();
    config.m_proxyPassword = proxy.value(QStringLiteral("pass")).toString();
    config.m_proxyPort = proxy.value(QStringLiteral("port")).toVariant().toUInt();
    config.m_proxyUser = proxy.value(QStringLiteral("user")).toString();

    // gui.exe:0x14011FFE3-0x1401203B2. Cookies are constructed value first,
    // then name; domain and path are applied only when their keys exist.
    for (const QJsonValue &cookieValue : http.value(QStringLiteral("cookies")).toArray()) {
        const QJsonObject cookieObject = cookieValue.toObject();
        QNetworkCookie cookie(cookieObject.value(QStringLiteral("name")).toString().toUtf8(),
                               cookieObject.value(QStringLiteral("value")).toString().toUtf8());
        if (cookieObject.contains(QStringLiteral("domain")))
            cookie.setDomain(cookieObject.value(QStringLiteral("domain")).toString());
        if (cookieObject.contains(QStringLiteral("path")))
            cookie.setPath(cookieObject.value(QStringLiteral("path")).toString());
        config.m_httpCookies.append(cookie);
    }

    // gui.exe:0x14011FCA3-0x14011FFCF. Only the first HTTP authentication
    // entry is consulted, and its user/password are retained only if that
    // entry is enabled. `manualLogin` changes a separate native mode value;
    // it does not populate the credentials forwarded to NetworkManager.
    // gui.exe:0x14012038E-0x14012074D. Technologies array parsing.
    // Each entry has "tech" (name:version format) and "path" fields.
    for (const QJsonValue &techValue : json.value(QStringLiteral("technologies")).toArray()) {
        const QJsonObject techObject = techValue.toObject();
        const QString techField = techObject.value(QStringLiteral("tech")).toString();
        const QString path = techObject.value(QStringLiteral("path")).toString();

        TechnologyEntry entry;
        entry.path = path;

        // Parse "name:version" format. Version defaults to 1 if not present.
        const QString name = techField.section(u':', 0, 0);
        const QString versionStr = techField.section(u':', 1, 1);
        entry.name = name;
        if (versionStr.isNull() || versionStr.isEmpty()) {
            entry.version = QVariant(1);
        } else {
            entry.version = QVariant(versionStr);
        }
        config.m_technologies.append(entry);
    }

    const QJsonArray httpAuthentication = json.value(QStringLiteral("authentication"))
                                              .toObject()
                                              .value(QStringLiteral("http"))
                                              .toArray();
    if (!httpAuthentication.isEmpty()) {
        const QJsonObject firstAuthentication = httpAuthentication.first().toObject();
        if (firstAuthentication.value(QStringLiteral("enabled")).toBool(false)) {
            config.m_authenticationUser = firstAuthentication.value(
                QStringLiteral("user")).toString();
            config.m_authenticationPassword = firstAuthentication.value(
                QStringLiteral("pass")).toString();
        }
    }
    return config;
}

QNetworkProxy ScanConfig::networkProxy() const
{
    // gui.exe:0x140121070 / 0x140120FF0.
    QNetworkProxy::ProxyType type;
    if (m_proxyType == QStringLiteral("system"))
        type = QNetworkProxy::DefaultProxy;
    else if (m_proxyType == QStringLiteral("noproxy"))
        type = QNetworkProxy::NoProxy;
    else if (m_proxyType == QStringLiteral("http"))
        type = QNetworkProxy::HttpProxy;
    else if (m_proxyType == QStringLiteral("socks"))
        type = QNetworkProxy::Socks5Proxy;
    else
        qFatal("invalid proxy type: %s", qPrintable(m_proxyType));

    return QNetworkProxy(type, m_proxyHost, m_proxyPort, m_proxyUser, m_proxyPassword);
}

QRegularExpression ScanConfig::globExpression(const QString &source)
{
    // Exact pattern compiler at gui.exe:0x1400831B0. A blank pattern or `*`
    // yields a null QRegularExpression; Qt treats its empty pattern as a
    // match at every position.
    const QString trimmed = source.trimmed();
    if (trimmed.isEmpty() || trimmed == QStringLiteral("*"))
        return {};

    QString pattern = QRegularExpression::escape(trimmed.toLower());
    pattern.replace(QStringLiteral("\\?"), QStringLiteral(".{0,1}"), Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\+"), QStringLiteral(".+?"), Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\*"), QStringLiteral(".*?"), Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\%"), QStringLiteral("[^/\\s\\?]+?"), Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\#"), QStringLiteral("\\d"), Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\[md5\\]"), QStringLiteral("[a-f0-9]{32}"),
                    Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\[year\\]"), QStringLiteral("20\\d{2}"),
                    Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\[guid\\]"),
                    QStringLiteral("[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?"),
                    Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\[base64\\]"),
                    QStringLiteral("^([a-z0-9A-Z/+]{2,}==|(?=.*(?:[g-z]))[a-z0-9A-Z+]{28,})$"),
                    Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\[seo\\]"), QStringLiteral("(:?(-|\\/))[a-z-]{20,}"),
                    Qt::CaseSensitive);
    pattern.replace(QStringLiteral("\\[non\\-english\\]"), QStringLiteral("[^\\x20-\\x7E]+"),
                    Qt::CaseSensitive);
    return QRegularExpression(QStringLiteral("^") + pattern + QStringLiteral("$"),
                              QRegularExpression::CaseInsensitiveOption);
}

ScanConfig ScanConfig::loadFile(const QString &path, QString *error) {
    QFile input(path);
    if (!input.open(QIODevice::ReadOnly)) {
        if (error) *error = input.errorString();
        return {};
    }

    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(input.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = parseError.errorString();
        return {};
    }
    return fromJson(document.object());
}

QList<QUrl> ScanConfig::initialUrls() const
{
    // gui.exe:0x140031910 reads target.items. Its TargetItem URL parser at
    // 0x140031500/0x140032070 accepts a string or array in `data` and calls
    // QUrl::fromUserInput for every value.
    QList<QUrl> urls;
    const QJsonArray items = m_json.value(QStringLiteral("target"))
                                 .toObject()
                                 .value(QStringLiteral("items"))
                                 .toArray();
    for (const QJsonValue &itemValue : items) {
        const QJsonObject item = itemValue.toObject();
        if (item.value(QStringLiteral("type")).toString()
            != QStringLiteral("url")) {
            // Native factories also handle `file` and `http` at
            // 0x1401218E0 and 0x140121E00. They have not been reconstructed;
            // this URL-only accessor must not synthesize their semantics.
            continue;
        }

        const QJsonValue data = item.value(QStringLiteral("data"));
        if (data.isString()) {
            urls.append(QUrl::fromUserInput(data.toString()));
        } else if (data.isArray()) {
            for (const QJsonValue &value : data.toArray())
                urls.append(QUrl::fromUserInput(value.toString()));
        }
    }
    return urls;
}

QList<QSharedPointer<urlItem>> ScanConfig::initialRequestItems() const
{
    // gui.exe:0x140031910 drives TargetItem parsing. Its output is converted
    // by gui.exe:0x140122140, which dispatches to URL (0x1401223A0), file
    // (0x1401218E0), or raw HTTP (0x140121E00) factories in original order.
    QList<QSharedPointer<urlItem>> items;
    const QJsonArray targetItems = m_json.value(QStringLiteral("target"))
                                      .toObject()
                                      .value(QStringLiteral("items"))
                                      .toArray();
    for (const QJsonValue &itemValue : targetItems) {
        const QJsonObject item = itemValue.toObject();
        const QString type = item.value(QStringLiteral("type")).toString();
        const QJsonValue data = item.value(QStringLiteral("data"));

        if (type == QStringLiteral("url")) {
            if (data.isString()) {
                appendUrlItem(items, QUrl::fromUserInput(data.toString()));
            } else if (data.isArray()) {
                for (const QJsonValue &value : data.toArray())
                    appendUrlItem(items, QUrl::fromUserInput(value.toString()));
            }
            continue;
        }

        if (type == QStringLiteral("file")) {
            // gui.exe:0x140030EF0 reads data.name/path/content. The factory
            // at 0x1401218E0 ignores name, opens path only when content is a
            // null QString, then separately processes non-empty \n fragments.
            const QJsonObject fileData = data.toObject();
            const QString path = fileData.value(QStringLiteral("path")).toString();
            const QString content = fileData.value(QStringLiteral("content")).toString();
            if (content.isNull()) {
                QFile input(path);
                if (!input.open(QIODevice::ReadOnly))
                    throw std::runtime_error("Could not open the file!");
                QTextStream stream(&input);
                while (!stream.atEnd())
                    appendUrlItem(items, QUrl::fromUserInput(stream.readLine()));
            }

            const QList<QString> lines = content.split(
                QRegularExpression(QStringLiteral("\\n")), Qt::SkipEmptyParts);
            for (const QString &line : lines)
                appendUrlItem(items, QUrl::fromUserInput(line.trimmed()));
            continue;
        }

        if (type == QStringLiteral("http")) {
            // gui.exe:0x140031150 reads data.url/method/body and ordered
            // data.headers {name,value} entries. Factory 0x140121E00 makes a
            // urlItem and stores each header under its lower-case lookup key.
            const QJsonObject httpData = data.toObject();
            const auto rawItem = QSharedPointer<urlItem>::create(
                QUrl::fromUserInput(httpData.value(QStringLiteral("url"))
                                        .toString()).toString(),
                requestKindForTargetMethod(
                    httpData.value(QStringLiteral("method")).toString()),
                httpData.value(QStringLiteral("body")).toString().toUtf8());
            for (const QJsonValue &headerValue :
                 httpData.value(QStringLiteral("headers")).toArray()) {
                const QJsonObject header = headerValue.toObject();
                const QByteArray name = header.value(QStringLiteral("name"))
                                            .toString().toUtf8();
                const QByteArray value = header.value(QStringLiteral("value"))
                                             .toString().toUtf8();
                rawItem->headers[name.toLower()].append(qMakePair(name, value));
            }
            items.append(rawItem);
            continue;
        }

        // gui.exe:0x1400318F6 throws this exact message for a fourth type.
        throw std::runtime_error("Unknown TargetItem type");
    }
    return items;
}

bool ScanConfig::isValid(QString *error) const {
    // Evidence: sms.exe ScanConfig_validate (0x14001E250) rejects empty config
    // and reports exact failures for target, proxy, User-Agent, crawl depth,
    // basic authentication and exit severity.  More detailed validation still
    // needs line-by-line reconstruction.
    if (m_json.isEmpty()) {
        if (error) *error = QStringLiteral("No valid target provided");
        return false;
    }
    const auto target = m_json.value("target");
    if (!target.isObject() || target.toObject().value("items").toArray().isEmpty()) {
        if (error) *error = QStringLiteral("No valid target provided");
        return false;
    }
    const auto http = m_json.value("http").toObject();
    if (http.contains("userAgent") && http.value("userAgent").toString().isEmpty()) {
        if (error) *error = QStringLiteral("User agent cannot be empty");
        return false;
    }
    const auto crawler = m_json.value("crawler").toObject();
    const auto depth = crawler.value("depth");
    if (depth.isDouble() && depth.toInt() < 0) {
        if (error) *error = QStringLiteral("Crawl depth should be 0 or a greater number");
        return false;
    }
    return true;
}
