#pragma once
#include "scriptnativeports.h"
#include <QHash>
#include <QSet>
#include <QThreadPool>
#include <QTimer>
#include <QLoggingCategory>
#include <QRunnable>
#include <atomic>
#include <deque>
#include <memory>

// Source representation of native state allocated at 0x140113EB0.
struct ScriptRunnerState {
    QMutex mutex;
    std::unique_ptr<QRunnable> runnable;
    QSharedPointer<NativeScriptInstancePort> instance;
    std::deque<ScriptWorkItem> queue;
    ScriptURI descriptor;
    qint32 parallelism = 1;
    bool active = false;
    qint64 lastActivity = 0;
};

class ScriptRunner final : public QObject {
    Q_OBJECT
public:
    // catalog is an explicit source adapter for the native singleton dependency.
    // This component is not wired into Scanner until its catalog is recovered.
    explicit ScriptRunner(NativeScriptCatalogPort &catalog, qint32 mode = 0,
                          QObject *parent = nullptr);
    ~ScriptRunner() override;
    void enqueue(const ScriptWorkItem &work, const QList<ScriptURI> &scripts);
    void stop();
    void start();
    void setMaxThreadCount(qint32 count);
    QPair<qint64, qint64> counters() const;
    void collectIdle();
public slots:
    void checkFinished();
signals:
    void finished();
    void allFinished();
private:
    friend struct ScriptRunnerTestAccess;
    QSharedPointer<ScriptRunnerState> createState(const ScriptURI &descriptor);
    QSharedPointer<ScriptRunnerState> selectState(const ScriptURI &descriptor);
    void process(ScriptRunnerState *state);
    NativeScriptCatalogPort &m_catalog;
    QLoggingCategory m_log;
    QMutex m_stateMutex; // native+40
    QMutex m_idleMutex; // native+48
    QMultiHash<QString, QSharedPointer<ScriptRunnerState>> m_states; // +56
    QHash<QString, qint32> m_instanceCounts; // +72
    QSet<QString> m_idleKeys; // +80
    QThreadPool m_pool; // +88
    QTimer m_gcTimer; // +104
    std::atomic_bool m_finishedNotified{true}; // +120
    qint32 m_idleSeconds = 20; // +124
    std::atomic<qint64> m_completed{0}; // +128
    std::atomic<qint64> m_submitted{0}; // +136
    qint32 m_mode = 0; // +144
};
