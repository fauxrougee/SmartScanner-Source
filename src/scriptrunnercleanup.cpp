// gui.exe:0x1401154D0/0x140115870/0x1401158A0. Full-key idle eviction only.
#include "scriptrunner.h"

#include <QDateTime>
#include <QMutexLocker>

void ScriptRunner::stop()
{
    m_mode = 2;
}

void ScriptRunner::checkFinished()
{
    bool expected = false;
    if (m_completed.load() == m_submitted.load()
        && m_finishedNotified.compare_exchange_strong(expected, true)) {
        emit allFinished();
    }
}

void ScriptRunner::collectIdle()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 threshold = 1000 * static_cast<qint64>(m_idleSeconds);

    QList<QString> idleSnapshot;
    {
        QMutexLocker idleLocker(&m_idleMutex);
        idleSnapshot = m_idleKeys.values();
    }

    for (const QString &key : idleSnapshot) {
        bool removeKey = false;
        {
            QMutexLocker stateLocker(&m_stateMutex);
            auto range = m_states.equal_range(key);
            if (range.first != range.second) {
                bool allQualify = true;
                for (auto it = range.first; it != range.second; ++it) {
                    ScriptRunnerState *state = it.value().data();
                    QMutexLocker stateLocker(&state->mutex);
                    const bool idle = !state->active
                                      && state->queue.empty()
                                      && (now - state->lastActivity) > threshold;
                    if (!idle) {
                        allQualify = false;
                        break;
                    }
                }
                if (allQualify) {
                    m_states.remove(key);
                    m_instanceCounts.remove(key);
                    removeKey = true;
                }
            }
        }
        if (removeKey) {
            QMutexLocker idleLocker(&m_idleMutex);
            m_idleKeys.remove(key);
        }
    }
}
