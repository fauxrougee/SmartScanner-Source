#include "opensslhelper.h"

#include <QCoreApplication>
#include <QDir>
#include <QProcessEnvironment>

OpenSSL::OpenSSL(const QString &program, QObject *parent)
    : QObject(parent), m_program(program) {
    // Native code creates an environment, inserts exactly this key/value pair,
    // and assigns it to the QProcess.
    QProcessEnvironment environment;
    environment.insert(QStringLiteral("OPENSSL_CONF"), QStringLiteral("./config.cfg"));
    m_process.setProcessEnvironment(environment);
}

OpenSSL::~OpenSSL() {
    // Directly observed native destruction order. QProcess tolerates both calls
    // if no child process was started.
    m_process.kill();
    m_process.waitForFinished(30000);
}

bool OpenSSL::execute(const QStringList &arguments) {
    // sms.exe:0x1400FB5A0. This is a literal path construction, including the
    // trailing slash expectations of SMART_SCANNER_OPENSSL_PATH.
    m_standardError.clear();
    m_standardOutput.clear();

    const QString relativeProgram = qEnvironmentVariable(
        "SMART_SCANNER_OPENSSL_PATH", QStringLiteral("./openssl/"))
        + m_program + QStringLiteral("/openssl.exe");
    const QString executable = QDir(QCoreApplication::applicationDirPath()).filePath(relativeProgram);

    m_process.start(executable, arguments, QIODevice::ReadWrite);
    if (!m_process.waitForStarted(30000)) {
        m_standardError = m_process.errorString().toUtf8();
        return false;
    }

    while (m_process.state() != QProcess::NotRunning) {
        if (!m_process.waitForReadyRead(30000))
            break;

        m_standardError.append(m_process.readAllStandardError());
        m_standardOutput.append(m_process.readAllStandardOutput());
        if (hasError() || m_standardOutput.contains("BEGIN CERTIFICATE"))
            break;
    }

    m_standardError.append(m_process.readAllStandardError());
    m_standardOutput.append(m_process.readAllStandardOutput());
    m_process.terminate();
    m_process.kill();
    m_process.waitForFinished(30000);

    return !hasError() && m_standardOutput.contains("BEGIN CERTIFICATE");
}

bool OpenSSL::hasError() const {
    // sms.exe:0x1400FB8D0. QByteArray::contains is case-sensitive.
    return m_standardError.contains("failure") || m_standardError.contains("error");
}
