#pragma once

#include <QString>
#include <QStringList>
#include <QMap>
#include <QRegularExpression>
#include <QList>

namespace Fingerprint {

// Server signature
struct ServerSignature {
    QString name;
    QRegularExpression pattern;
    QString header;
};

// CMS signature
struct CmsSignature {
    QString name;
    QRegularExpression pattern;
    QString location;
};

// JavaScript framework signature
struct JsFrameworkSignature {
    QString name;
    QRegularExpression pattern;
    QString version;
};

// WAF signature
struct WafSignature {
    QString name;
    QRegularExpression pattern;
    QString location;
    QString bypassHint;
};

// CDN signature
struct CdnSignature {
    QString name;
    QRegularExpression pattern;
    QString location;
};

// Analytics signature
struct AnalyticsSignature {
    QString name;
    QRegularExpression pattern;
    QString type;
};

// OS signature
struct OsSignature {
    QString name;
    QRegularExpression pattern;
    QString location;
};

// Database signature
struct DatabaseSignature {
    QString name;
    QRegularExpression pattern;
    QString location;
};

// Detected technology
struct DetectedTech {
    QString name;
    QString version;
    QString category;
    double confidence = 0.0;
};

// Fingerprint result
struct FingerprintResult {
    QList<DetectedTech> technologies;
    QStringList warnings;
};

// Get signature lists
QList<ServerSignature> getServerSignatures();
QList<CmsSignature> getCmsSignatures();
QList<JsFrameworkSignature> getJsFrameworkSignatures();
QList<WafSignature> getWafSignatures();
QList<CdnSignature> getCdnSignatures();
QList<AnalyticsSignature> getAnalyticsSignatures();
QList<OsSignature> getOsSignatures();
QList<DatabaseSignature> getDatabaseSignatures();

// Main fingerprinting function
FingerprintResult fingerprint(const QString &body, const QMap<QString, QString> &headers);

} // namespace Fingerprint
