#ifndef IDORDETECTOR_H
#define IDORDETECTOR_H

#include <QString>
#include <QStringList>
#include <QUrl>
#include <QVariant>
#include <QList>

class IdorDetector
{
public:
    enum class IdorType {
        None,
        DirectObjectReference,
        PredictableId,
        ParameterManipulation,
        PathTraversal,
        MassAssignment
    };
    struct IdorCandidate {
        QString parameter;
        QString value;
        QString location;
        IdorType type;
        int likelihood;
    };

    IdorDetector() = default;
    ~IdorDetector() = default;

    QList<IdorCandidate> analyze(const QUrl &url) const;
    QList<IdorCandidate> analyzeBody(const QString &requestBody, const QString &contentType) const;
    IdorType detect(const QString &response1, const QString &response2) const;
    bool isVulnerable(const QString &response1, const QString &response2) const;

    static QStringList getSensitiveParameters();
    static QStringList getNumericIdPayloads(int originalId);
    static QStringList getUuidPayloads(const QString &originalUuid);
    static int severityLevel(IdorType type);
};

#endif // IDORDETECTOR_H
