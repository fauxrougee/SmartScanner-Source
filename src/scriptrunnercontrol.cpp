#include "scriptrunner.h"
#include <QMutexLocker>

// gui.exe:0x140117E00. Starts every inactive state, even with an empty queue.
void ScriptRunner::start()
{
    m_mode = 1;
    QMutexLocker managerLocker(&m_stateMutex);
    for (auto it = m_states.begin(); it != m_states.end(); ++it) {
        const auto &state = it.value();
        QMutexLocker stateLocker(&state->mutex);
        if (!state->active) {
            state->active = true;
            m_pool.start(state->runnable.get(), 0);
        }
    }
}

// gui.exe:0x140117DF0; forwards without clamping.
void ScriptRunner::setMaxThreadCount(qint32 count)
{
    m_pool.setMaxThreadCount(count);
}

// gui.exe:0x1401175E0; completed first, submitted second, without a mutex.
QPair<qint64, qint64> ScriptRunner::counters() const
{
    return {m_completed.load(), m_submitted.load()};
}
