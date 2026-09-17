// gui.exe:0x1401154E0/0x140116ED0/0x140117F60. Runnable ownership is retained.
#include "scriptrunner.h"
#include <QDateTime>
#include <memory>
#include <climits>
#include <QMutexLocker>

QSharedPointer<ScriptRunnerState> ScriptRunner::createState(const ScriptURI &descriptor)
{
    auto state = QSharedPointer<ScriptRunnerState>::create();
    state->descriptor = descriptor;

    ScriptRunnerState *raw = state.data();
    state->runnable = std::unique_ptr<QRunnable>(
        QRunnable::create([this, raw]() { this->process(raw); }));
    state->runnable->setAutoDelete(false);

    const qint64 createdAt = QDateTime::currentMSecsSinceEpoch();
    {
        QMutexLocker locker(&state->mutex);
        state->lastActivity = createdAt;
    }

    const QString key = descriptor.toString();
    m_states.insert(key, state);
    ++m_instanceCounts[key];

    return state;
}

QSharedPointer<ScriptRunnerState> ScriptRunner::selectState(const ScriptURI &descriptor)
{
    const QString key = descriptor.toString();
    auto range = m_states.equal_range(key);
    if (range.first == range.second)
    {
        return createState(descriptor);
    }

    int maxParallelism = 1;
    int leastQueued = INT_MAX;
    QSharedPointer<ScriptRunnerState> chosen;

    for (auto it = range.first; it != range.second; ++it)
    {
        const QSharedPointer<ScriptRunnerState> &candidate = it.value();
        if (candidate.isNull())
            continue;

        bool active;
        qint32 parallelism;
        qint32 queueSize;
        {
            QMutexLocker locker(&candidate->mutex);
            active = candidate->active;
            parallelism = candidate->parallelism;
            queueSize = static_cast<qint32>(candidate->queue.size());
        }

        if (active)
        {
            if (maxParallelism < parallelism)
                maxParallelism = parallelism;

            if (queueSize < leastQueued)
            {
                leastQueued = queueSize;
                chosen = candidate;
            }
        }
        else
        {
            const qint64 now = QDateTime::currentMSecsSinceEpoch();
            {
                QMutexLocker locker(&candidate->mutex);
                candidate->lastActivity = now;
            }
            return candidate;
        }
    }

    const qint32 count = m_instanceCounts.value(key, 0);
    if (count < maxParallelism)
    {
        auto created = createState(descriptor);
        if (!created.isNull())
            return created;
    }

    if (chosen)
    {
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        {
            QMutexLocker locker(&chosen->mutex);
            chosen->lastActivity = now;
        }
    }
    return chosen;
}

void ScriptRunner::enqueue(const ScriptWorkItem &work, const QList<ScriptURI> &scripts)
{
    for (const ScriptURI &descriptor : scripts)
    {
        if (m_mode == 2)
            return;

        QMutexLocker managerLocker(&m_stateMutex);
        auto state = selectState(descriptor);
        if (state.isNull())
        {
            continue;
        }

        m_finishedNotified.store(false);

        m_submitted.fetch_add(1);

        if (m_mode == 1)
        {
            {
                QMutexLocker stateLocker(&state->mutex);
                state->queue.push_back(work);
                if (!state->active)
                {
                    state->active = true;
                    QThreadPool *pool = &m_pool;
                    pool->start(state->runnable.get(), 0);
                }
            }
        }
        else
        {
            QMutexLocker stateLocker(&state->mutex);
            state->queue.push_back(work);
        }

    }
}
