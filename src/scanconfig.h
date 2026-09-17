#pragma once

#include "httprequestrawpacket.h"

#include <QJsonObject>
#include <QList>
#include <QNetworkCookie>
#include <QNetworkProxy>
#include <QPair>
#include <QRegularExpression>
#include <QSharedPointer>
#include <QString>
#include <QUrl>
#include <QVariant>

// Reconstruction label; native rule contains regex fields +0/+8/+16 and
// the vector mask +24. gui.exe:0x14011F0C5-0x14011F104.
struct ParameterExclusionRule {
    QRegularExpression field00;
    QRegularExpression field08;
    QRegularExpression field10;
    qint32 field18 = 0;
};

// gui.exe:0x14011F038-0x14011F152. Technology entries with name, version, path.
struct TechnologyEntry {
    QString name;
    QVariant version;
    QString path;
};

class ScanConfig final {
public:
    ScanConfig();

    static ScanConfig fromJson(const QJsonObject &json);
    static ScanConfig loadFile(const QString &path, QString *error = nullptr);

    [[nodiscard]] const QJsonObject &json() const noexcept { return m_json; }
    [[nodiscard]] QJsonObject &json() noexcept { return m_json; }
    // gui.exe:0x14011DC0D-0x14011DE09.
    [[nodiscard]] const QStringList &testScripts() const noexcept { return m_testScripts; }
    [[nodiscard]] qint32 cpuThreads() const noexcept { return m_cpuThreads; }
    // gui.exe ScanConfig JSON parser: field +0x1B8 is initialized to -1 and
    // overwritten only when crawler.depth is not a JSON boolean.
    [[nodiscard]] int crawlerDepth() const noexcept { return m_crawlerDepth; }
    [[nodiscard]] bool crawlerEnabled() const noexcept { return m_crawlerDepth != 0; }
    [[nodiscard]] quint64 crawlerCount() const noexcept { return m_crawlerCount; }
    [[nodiscard]] const QRegularExpression &scopeExpression() const noexcept {
        return m_scopeExpression;
    }
    [[nodiscard]] const QList<QRegularExpression> &fileExclusions() const noexcept {
        return m_fileExclusions;
    }
    [[nodiscard]] const QList<QRegularExpression> &urlExclusions() const noexcept {
        return m_urlExclusions;
    }
    [[nodiscard]] quint32 maxParallelRequests() const noexcept {
        return m_maxParallelRequests;
    }
    [[nodiscard]] const QString &authenticationUser() const noexcept {
        return m_authenticationUser;
    }
    [[nodiscard]] const QString &authenticationPassword() const noexcept {
        return m_authenticationPassword;
    }
    [[nodiscard]] qint64 httpTimeout() const noexcept { return m_httpTimeout; }
    [[nodiscard]] const QString &userAgent() const noexcept { return m_userAgent; }
    [[nodiscard]] const QList<QPair<QByteArray, QByteArray>> &httpHeaders() const noexcept {
        return m_httpHeaders;
    }
    // gui.exe:0x140120FF0 constructs this QNetworkProxy from the five fields
    // parsed below. Invalid type spellings terminate in 0x140121070.
    [[nodiscard]] QNetworkProxy networkProxy() const;
    [[nodiscard]] const QList<QNetworkCookie> &httpCookies() const noexcept {
        return m_httpCookies;
    }
    // gui.exe:0x140031910 / 0x140032070. These are only the URLs recovered
    // from TargetItem type `url`; `file` and `http` target factories remain
    // deliberately outside this partial reconstruction.
    [[nodiscard]] QList<QUrl> initialUrls() const;
    // gui.exe:0x140031500 chooses URL/file/raw-HTTP TargetItem parsers, then
    // gui.exe:0x140122140 dispatches their result to the corresponding
    // urlItem factory. The raw list preserves target order.
    [[nodiscard]] QList<QSharedPointer<urlItem>> initialRequestItems() const;
    [[nodiscard]] bool isValid(QString *error = nullptr) const;
    [[nodiscard]] quint32 vectorFlags() const noexcept { return m_vectorFlags; }
    [[nodiscard]] bool evaluateJsWithChromium() const noexcept { return m_evaluateJsWithChromium; }
    [[nodiscard]] int crawlStartDepth() const noexcept { return m_crawlStartDepth; }
    [[nodiscard]] bool isManualScope() const noexcept { return m_isManualScope; }
    [[nodiscard]] bool scanAbovePath() const noexcept { return m_scanAbovePath; }
    [[nodiscard]] bool scanSubDomains() const noexcept { return m_scanSubDomains; }
    [[nodiscard]] const QList<TechnologyEntry> &technologies() const noexcept {
        return m_technologies;
    }
    [[nodiscard]] QSharedPointer<QList<ParameterExclusionRule>> parameterExclusions() const {
        return m_parameterExclusions;
    }
    // gui.exe:0x1400EA5B0. Copy the shared pointer, not its QList contents.
    [[nodiscard]] QSharedPointer<QList<HtmlFormValueRule>> valueRules() const {
        return m_valueRules;
    }

private:
    [[nodiscard]] static QRegularExpression globExpression(const QString &pattern);

    QJsonObject m_json;
    QStringList m_testScripts;
    qint32 m_cpuThreads = -1;
    int m_crawlerDepth = -1;
    quint64 m_crawlerCount = 0;
    QRegularExpression m_scopeExpression;
    QList<QRegularExpression> m_fileExclusions;
    QList<QRegularExpression> m_urlExclusions;
    quint32 m_maxParallelRequests = 6;
    QString m_authenticationUser;
    QString m_authenticationPassword;
    qint64 m_httpTimeout = 90000;
    QString m_userAgent;
    QList<QPair<QByteArray, QByteArray>> m_httpHeaders;
    QString m_proxyType = QStringLiteral("noproxy");
    QString m_proxyHost;
    QString m_proxyUser;
    QString m_proxyPassword;
    quint16 m_proxyPort = 1;
    bool m_evaluateJsWithChromium = false;
    int m_crawlStartDepth = 0;
    bool m_isManualScope = false;
    bool m_scanAbovePath = false;
    bool m_scanSubDomains = false;
    QList<TechnologyEntry> m_technologies;
    QList<QNetworkCookie> m_httpCookies;
    // gui.exe:0x14011CE00 allocates an empty but non-null shared rule list.
    QSharedPointer<QList<HtmlFormValueRule>> m_valueRules =
        QSharedPointer<QList<HtmlFormValueRule>>::create();
    // gui.exe:0x14011CE00: +448 mask, +56/+64 non-null shared rule list.
    quint32 m_vectorFlags = 31;
    QSharedPointer<QList<ParameterExclusionRule>> m_parameterExclusions =
        QSharedPointer<QList<ParameterExclusionRule>>::create();
};
