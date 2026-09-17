#pragma once

#include "duration.h"
#include "crawler.h"
#include "filelist.h"
#include "issuedb.h"
#include "networkmanager.h"
#include "manipulator.h"
#include "scanconfig.h"
#include "scriptcatalog.h"
#include "scriptrunner.h"
#include "scripttrigger.h"

#include <QObject>
#include <QJsonArray>
#include <QDate>
#include <QElapsedTimer>
#include <QUuid>
#include <QVariantMap>

class Scanner final : public QObject {
    Q_OBJECT
public:
    // Literal integer mapping observed in sms.exe Scanner_setStatus 0x1400E38B0.
    enum ScanStatus { Idle = 0, Scanning = 1, Finished = 2, Stopping = 3,
                      Stopped = 4, Pausing = 5, Paused = 6 };
    Q_ENUM(ScanStatus)

    explicit Scanner(QObject *parent = nullptr);
    [[nodiscard]] ScanStatus status() const noexcept { return m_status; }
    [[nodiscard]] const ScanConfig &config() const noexcept { return m_config; }
    [[nodiscard]] qint64 elapsedMilliseconds() const noexcept;
    [[nodiscard]] QDate startedDate() const noexcept { return m_duration.date(); }
    [[nodiscard]] const Duration &duration() const noexcept { return m_duration; }
    // sms.exe ScanConfig target summary at 0x1401209E0, captured while the
    // target factories are applied so report generation does not re-read files.
    [[nodiscard]] const QString &reportTarget() const noexcept { return m_reportTarget; }
    // gui.exe:0x1400E9470, called through Scanner's secondary interface by
    // WebInterface_getUpdate. Keys whose owning native component is not yet
    // reconstructed are intentionally absent; the WebInterface's native
    // lookup behavior supplies QVariant(0) for an absent key.
    [[nodiscard]] QVariantMap updateValues() const;
    [[nodiscard]] QUuid id() const noexcept { return m_id; }
    [[nodiscard]] IssueDb &issueDb() noexcept { return m_issueDb; }
    [[nodiscard]] const IssueDb &issueDb() const noexcept { return m_issueDb; }
    [[nodiscard]] FileList &fileList() noexcept { return m_fileList; }
    [[nodiscard]] const FileList &fileList() const noexcept { return m_fileList; }
    [[nodiscard]] Crawler &crawler() noexcept { return m_crawler; }
    [[nodiscard]] const Crawler &crawler() const noexcept { return m_crawler; }
    [[nodiscard]] Manipulator &manipulator() noexcept { return m_manipulator; }
    [[nodiscard]] QJsonArray issuesAsJson() const;

    // Direct decision table from gui.exe:0x1400E8680. The ScriptTrigger and
    // Manipulator consumers have separate unreconstructed state machines, so
    // this value records only which native route is eligible for a response.
    struct ResponseRoutingDecision {
        bool scriptTriggerEvent4 = false;
        bool scriptTriggerEvent8 = false;
        bool manipulator = false;
    };
    [[nodiscard]] static ResponseRoutingDecision responseRoutingDecision(
        ScanStatus status, const NetworkManager::ResponsePointer &response,
        bool withinScope) noexcept;

public slots:
    // gui.exe:0x1400E8F20. The native routine also forwards configuration to
    // components not yet reconstructed in this source tree.
    void applyConfig(const ScanConfig &config);
    // gui.exe:0x1400E9400
    void start();
    void stop();
    void pause();
    void resume();
    void checkFinished();
    void continueScan();

signals:
    // Exact Qt meta-object names observed in Scanner constructors.
    void finished();
    void statusChanged(Scanner::ScanStatus status);
    void log(int type, const QString &category, const QString &message);
    void issuesUpdated(const QJsonArray &issues);

private:
    void setStatus(ScanStatus status);
    // gui.exe:0x1400E8680.  The first scheduling call is known; its parser,
    // ScriptTrigger and Manipulator targets are not reconstructed yet.
    void requestFinished(NetworkManager::ResponsePointer response);

    ScanConfig m_config;
    ScanStatus m_status = Idle;
    Duration m_duration;
    QUuid m_id;
    NetworkManager m_networkManager;
    FileList m_fileList;
    IssueDb m_issueDb;
    Crawler m_crawler;
    Manipulator m_manipulator;
    ScriptCatalog m_scriptCatalog;
    QSharedPointer<ScriptRunner> m_scriptRunner;
    QSharedPointer<ScriptTrigger> m_scriptTrigger;
    // gui.exe Scanner configuration application: ScanConfig virtual slot 6
    // (+0x30) is tested and its non-zero result is stored at Scanner +0x98.
    bool m_crawlerEnabled = false;
    QElapsedTimer m_elapsed;
    qsizetype m_pendingRequests = 0;
    qsizetype m_pendingScripts = 0;
    QString m_reportTarget;
};
