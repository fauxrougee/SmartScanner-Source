// gui.exe:0x140118310. Native factory calls exposed through pure source ports.
#include "scriptrunner.h"

#include <QDateTime>
#include <QDebug>
#include <QMetaObject>
#include <QMutexLocker>

void ScriptRunner::process(ScriptRunnerState *state)
{
    while (true) {
        ScriptWorkItem work;
        QString idleKey;

        bool shouldExit = false;
        bool idle = false;
        {
            QMutexLocker locker(&state->mutex);
            state->lastActivity = QDateTime::currentMSecsSinceEpoch();

            if (state->queue.empty()) {
                state->active = false;
                idleKey = state->descriptor.toString();
                idle = true;
                shouldExit = true;
            } else if (!state->active) {
                shouldExit = true;
            } else {
                work = std::move(state->queue.front());
                state->queue.pop_front();
            }
        }

        if (shouldExit) {
            if (m_completed.load() == m_submitted.load())
                QMetaObject::invokeMethod(this, "checkFinished", Qt::QueuedConnection);
            if (idle) {
                QMutexLocker locker(&m_idleMutex);
                m_idleKeys.insert(idleKey);
            }
            return;
        }

        QSharedPointer<NativeScriptInstancePort> instance;
        {
            QMutexLocker locker(&state->mutex);
            instance = state->instance;
        }

        if (instance.isNull()) {
            QSharedPointer<NativeScriptInstancePort> created =
                m_catalog.create(state->descriptor);

            {
                QMutexLocker locker(&state->mutex);
                if (state->instance.isNull()) {
                    state->instance = created;
                }
                if (!state->instance.isNull()) {
                    const unsigned int maxInstances =
                        state->instance->maxInstances();
                    qint32 parallelism = 1;
                    if (maxInstances > 1u)
                        parallelism = static_cast<qint32>(maxInstances);
                    state->parallelism = parallelism;
                }
                instance = state->instance;
            }
        }

        if (!instance.isNull()) {
            instance->setResponse(work.response);
            instance->setParameter(work.parameter);
            instance->setEvent(work.event);
            instance->execute();
        } else {
            qWarning() << "script instance not available for"
                       << state->descriptor.toString() << "while processing"
                       << describeScriptWork(work);
        }

        m_completed.fetch_add(1, std::memory_order_acq_rel);
        emit finished();
    }

}
