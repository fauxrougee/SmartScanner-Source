// gui.exe:0x140114BF0 and 0x140114E70. Source catalog adapter remains external.
#include "scriptrunner.h"

#include <QDateTime>
#include <QThread>
#include <QMutexLocker>

ScriptRunner::ScriptRunner(NativeScriptCatalogPort &catalog, qint32 mode, QObject *parent)
    : QObject(parent)
    , m_catalog(catalog)
    , m_log("scanner.scripts")
    , m_mode(mode)
{

    const int ideal = QThread::idealThreadCount();
    int maxThreads = 2;
    if (ideal > 2) {
        maxThreads = ideal;
    }
    m_pool.setMaxThreadCount(maxThreads);
    m_gcTimer.setInterval(60000);

    connect(&m_gcTimer, &QTimer::timeout, this, &ScriptRunner::collectIdle);
    m_gcTimer.start();
}

ScriptRunner::~ScriptRunner()
{
    m_mode = 2;
    m_gcTimer.stop();

    {
        QMutexLocker locker(&m_stateMutex);
        for (auto it = m_states.begin(); it != m_states.end(); ++it) {
            const QSharedPointer<ScriptRunnerState> &state = it.value();
            QMutexLocker stateLocker(&state->mutex);
            state->active = false;
            state->queue.clear();
        }
    }

    m_pool.waitForDone();
}
