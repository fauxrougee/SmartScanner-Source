#pragma once

#include "scanner.h"

#include <QObject>
#include <QJsonArray>
#include <QJsonObject>

class WebInterface final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QJsonObject version READ version CONSTANT)
    Q_PROPERTY(QJsonObject userInfoAtStartup READ userInfoAtStartup CONSTANT)
    Q_PROPERTY(QJsonArray issues READ issues NOTIFY issuesUpdated)
    Q_PROPERTY(QJsonObject defaultScanConfig READ defaultScanConfig CONSTANT)
public:
    explicit WebInterface(QObject *parent = nullptr);

    [[nodiscard]] QJsonObject version() const;
    [[nodiscard]] QJsonObject userInfoAtStartup() const;
    [[nodiscard]] QJsonArray issues() const noexcept;

    // Names and parameter order are recovered from gui.exe WebInterface's
    // Qt meta-call switch at 0x14002B980.
    Q_INVOKABLE void newScan();
    Q_INVOKABLE void startScan(const QJsonObject &configJson);
    void startScan(const ScanConfig &config);
    Q_INVOKABLE void pauseScan();
    Q_INVOKABLE void resumeScan();
    Q_INVOKABLE void stopScan();
    Q_INVOKABLE void saveReport(const QString &reportTemplate, const QString &reportFormat,
                                const QJsonObject &data = {});
    Q_INVOKABLE void catchCookie(const QString &cookie);
    Q_INVOKABLE void registerLicense(const QString &license);
    Q_INVOKABLE QString removeLicense();
    Q_INVOKABLE void setUiUpdateEnabled(bool enabled);
    Q_INVOKABLE void alert(const QString &message);
    Q_INVOKABLE void handleLog(int type, const QString &category, const QString &message);
    Q_INVOKABLE QJsonObject getUpdate();
    Q_INVOKABLE QJsonObject getUserInfo() const;
    Q_INVOKABLE QString showOpenDialog(const QString &title, const QString &filters);
    Q_INVOKABLE QString showSaveDialog(const QString &title, const QString &filters);
    Q_INVOKABLE int showInfoMessage(const QString &title, const QString &text);
    Q_INVOKABLE int showWarningMessage(const QString &title, const QString &text);
    Q_INVOKABLE QJsonObject defaultScanConfig() const;
    Q_INVOKABLE bool saveScan(const QString &path) const;
    Q_INVOKABLE bool loadScan(const QString &path);

signals:
    // Signal names and their order originate from the WebInterface MOC data.
    void issuesUpdated(const QJsonArray &issues);
    void statusChanged(int status);
    void loadFinished(bool loaded);
    void printDone(bool ok, const QString &filePath);
    void registrationResults(int status, const QString &message, const QString &details);
    void log(int type, const QString &category, const QString &message);

private:
    Scanner *ensureScanner();
    QString assetPath(const QString &fileName) const;

    Scanner *m_scanner = nullptr;
    bool m_uiUpdatesEnabled = false;
    QString m_target;
    double m_progress = 0.0;
    int m_progressTicks = 0;
};
