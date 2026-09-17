#include <QCoreApplication>
#include <QProcess>
#include <QStringList>

namespace {

bool expectsRejection(const QString &program, const QStringList &arguments,
                      const QByteArray &expectedText)
{
    QProcess process;
    process.start(program, arguments);
    if (!process.waitForFinished(10000))
        return false;
    const QByteArray output = process.readAllStandardOutput() + process.readAllStandardError();
    return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 2
        && output.contains(expectedText);
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    if (application.arguments().size() != 2)
        return 1;

    const QString sms = application.arguments().at(1);
    // sms.exe:0x14001EC75, 0x14001EDE7, 0x14001F28A and 0x14001F63A.
    if (!expectsRejection(sms, {QStringLiteral("--proxy"),
                                QStringLiteral("socks5://localhost:1080")},
                          QByteArrayLiteral("Invalid proxy URL provided")))
        return 2;
    if (!expectsRejection(sms, {QStringLiteral("--auth-basic"), QStringLiteral("admin")},
                          QByteArrayLiteral("Invalid HTTP Basic authentication provided")))
        return 3;
    if (!expectsRejection(sms, {QStringLiteral("--crawl-depth"), QStringLiteral("-1")},
                          QByteArrayLiteral("Crawl depth should be 0 or a greater number")))
        return 4;
    if (!expectsRejection(sms, {QStringLiteral("--scope"), QStringLiteral("("),
                                QStringLiteral("--url"), QStringLiteral("https://example.invalid")},
                          QByteArrayLiteral("Scopre regex error")))
        return 5;
    return 0;
}
