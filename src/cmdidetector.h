#ifndef CMDIDETECTOR_H
#define CMDIDETECTOR_H

#include <QString>
#include <QStringList>

class CmdInjectionDetector
{
public:
    enum class OsType {
        Unknown,
        Unix,
        Windows
    };
    enum class InjectionType {
        None,
        CommandChaining,
        CommandSubstitution,
        PipeInjection,
        BacktickInjection,
        PathTraversal,
        TimeBasedBlind
    };
    CmdInjectionDetector() = default;
    ~CmdInjectionDetector() = default;

    OsType detectOs(const QString &responseBody) const;
    InjectionType detect(const QString &responseBody, const QString &expectedOutput) const;
    bool isVulnerable(const QString &responseBody) const;

    static QStringList getPayloads(OsType os);
    static QStringList getTimeBasedPayloads(OsType os, int delaySeconds);
    static int severityLevel(InjectionType type);
};

#endif // CMDIDETECTOR_H
