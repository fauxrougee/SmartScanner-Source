#pragma once

#include <QByteArray>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>

// Constructor/destructor reconstruction of native class OpenSSL from sms.exe
// 0x1400FB390 and 0x1400FB480. It is not the scanner-engine entry point.
class OpenSSL final : public QObject {
    Q_OBJECT
public:
    explicit OpenSSL(const QString &program, QObject *parent = nullptr);
    ~OpenSSL() override;

    [[nodiscard]] QString program() const { return m_program; }
    [[nodiscard]] QByteArray standardOutput() const { return m_standardOutput; }
    [[nodiscard]] QByteArray standardError() const { return m_standardError; }

    // Reconstructed from sms.exe:0x1400FB5A0. Returns true only if the helper
    // does not report "failure" or "error" on stderr and stdout contains the
    // literal PEM marker "BEGIN CERTIFICATE".
    bool execute(const QStringList &arguments);

private:
    [[nodiscard]] bool hasError() const;

    QString m_program;
    QByteArray m_standardOutput;
    QByteArray m_standardError;
    QProcess m_process;
};
