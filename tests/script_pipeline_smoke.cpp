// Offline fixtures for wave11 native traces. Fake catalog/instances below are
// test doubles, not reconstructed SmartScanner scripts. No network operations.
#include "scripttrigger.h"
#include "keyvalueinjectionvector.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QEvent>
#include <QMutexLocker>
#include <QStringList>

static void require(bool condition, const char *message)
{
    if (!condition)
        qFatal("%s", message);
}

struct ScriptRunnerTestAccess {
    static auto state(ScriptRunner &runner, const ScriptURI &uri)
    {
        QMutexLocker lock(&runner.m_stateMutex);
        return runner.m_states.value(uri.toString());
    }
    static auto select(ScriptRunner &runner, const ScriptURI &uri)
    {
        QMutexLocker lock(&runner.m_stateMutex);
        return runner.selectState(uri);
    }
    static void process(ScriptRunner &runner, ScriptRunnerState *state)
    {
        runner.process(state);
    }
    static bool wait(ScriptRunner &runner) { return runner.m_pool.waitForDone(5000); }
    static void idleKey(ScriptRunner &runner, const QString &key)
    {
        runner.m_idleKeys.insert(key);
    }
    static bool hasIdleKey(ScriptRunner &runner, const QString &key)
    {
        return runner.m_idleKeys.contains(key);
    }
    static qsizetype stateCount(ScriptRunner &runner, const QString &key)
    {
        return runner.m_states.count(key);
    }
};
struct ScriptTriggerTestAccess {
    static QList<ScriptURI> scripts(ScriptTrigger &trigger, quint64 type)
    {
        return trigger.m_scripts.value(type);
    }
};

class FixtureInstance final : public NativeScriptInstancePort {
public:
    QStringList calls;
    NetworkResponsePtr response;
    ParameterInjectionPtr parameter;
    Event event;
    void setResponse(const NetworkResponsePtr &value) override
    { calls.append("response"); response = value; }
    void setParameter(const ParameterInjectionPtr &value) override
    { calls.append("parameter"); parameter = value; }
    void setEvent(const Event &value) override
    { calls.append("event"); event = value; }
    void execute() override { calls.append("execute"); }
    quint32 maxInstances() const override { return 2; }
    quint32 defaultPriority() const override { return 10; }
    QList<quint64> hooks() const override { return {}; }
};
class FixtureCatalog final : public NativeScriptCatalogPort {
public:
    int creates = 0;
    bool missing = false;
    QSharedPointer<FixtureInstance> last;
    ScriptURI resolve(ScriptURI uri) override { return uri; }
    QSharedPointer<NativeScriptInstancePort> create(const ScriptURI &) override
    {
        ++creates;
        if (missing)
            return {};
        last = QSharedPointer<FixtureInstance>::create();
        return last;
    }
};

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    ScriptURI empty;
    require(empty.toString().isNull(), "null URI name retained");
    ScriptURI uri(QStringLiteral("  TeST @R=3,2,garbage,,68719476736;O=a%2cb+%253D;P=65536 "));
    require(uri.name == "test ", "trim once, not again before @");
    require(uri.triggers == QList<quint64>({1, 2, 2, quint64(1) << 36}),
            "uppercase regex, bit expansion, duplicates and invalid mask");
    require(uri.options == "a,b %3D" && uri.priority == 65536,
            "ordered nonrecursive decode and signed32 priority");
    uri.parse("NEXT");
    require(uri.name == "next" && uri.priority == 65536 && uri.triggers.size() == 4,
            "parsing without extras preserves old fields");
    uri.parse("next@r=4;p=2147483648");
    require(uri.priority == -1 && uri.triggers.last() == 4, "append triggers and reject int overflow");
    require(ScriptURI::splitTriggerMask(quint64(1) << 37).isEmpty(), "only native37 flags");
    ScriptURI encoding;
    encoding.name = "x";
    encoding.options = "=;@ ,+%/";
    require(encoding.toString() == "x@options=%3D%3B%40%20,+%/", "limited serialization escaping");

    Event cached{16, QStringLiteral("same"), 0};
    const quint64 hash = cached.identityHash();
    require(hash != 0, "fixture hash nonzero");
    cached.data = "changed";
    require(cached.identityHash() == hash, "native cache not auto invalidated");

    // gui.exe:0x1401073D0 builds qHash(QStringView{"evt:%1:%2"}) with
    // an unsigned-decimal type and QVariant::toString() data before caching it.
    Event fresh;
    fresh.type = quint64(5);
    fresh.data = QStringLiteral("payload");
    const QString expectedText = QStringLiteral("evt:%1:%2").arg(fresh.type)
            .arg(fresh.data.toString());
    const quint64 expected = qHash(QStringView(expectedText), size_t(0));
    require(fresh.field28 == 0, "field28 starts empty before hash");
    require(fresh.identityHash() == expected,
            "identity hash matches qHash of evt:<unsigned type>:<toString>");
    require(fresh.field28 == expected, "identity hash retained in cache field28");
    Event unsignedType;
    unsignedType.type = quint64(0xFFFFFFFFFFFFFFFFULL);
    unsignedType.data = -1;
    const QString unsignedText = QStringLiteral("evt:%1:%2").arg(unsignedType.type)
            .arg(unsignedType.data.toString());
    require(unsignedType.identityHash() == qHash(QStringView(unsignedText), size_t(0)),
            "type formatted unsigned decimal, data via QVariant::toString");

    FixtureCatalog catalog;
    auto runner = QSharedPointer<ScriptRunner>::create(catalog, 0);
    ScriptTrigger trigger(runner, catalog);
    trigger.setScripts({"late@r=16;p=9", "early@r=16,16;p=-2"});
    const auto scripts = ScriptTriggerTestAccess::scripts(trigger, 16);
    require(scripts.size() == 3 && scripts[0].priority == -2 && scripts[2].priority == 9,
            "signed priority order and duplicate hooks retained");
    require(!trigger.emitEvent(Event{17, {}, 0}), "exact key, not overlapping mask");
    require(trigger.emitEvent(Event{16, "data", 77}), "registered event submitted");
    require(runner->counters() == qMakePair(qint64(0), qint64(3)), "mode0 queued, not executed");
    require(!trigger.emitScript(QStringLiteral("EARLY"), Event{16, {}, 0}), "name lookup case sensitive");
    Event absent{8192, {}, 0};
    require(trigger.emitOnce(absent) == 0, "unregistered first once returns false");
    require(trigger.emitOnce(QStringLiteral("early"), absent) == -1,
            "failed once consumed across named/event overloads");
    runner->stop();
    require(trigger.emitEvent(Event{16, {}, 0}), "dispatch return independent of stopped runner");
    require(runner->counters().second == 3, "stopped runner drops new submissions");

    FixtureCatalog executionCatalog;
    ScriptRunner execution(executionCatalog, 0);
    ScriptURI executable("fixture@r=8");
    auto response = QSharedPointer<HttpResponse>::create();
    response->url = QUrl("https://fixture.invalid/");
    execution.enqueue({response, {}, Event{8, QStringLiteral("arg"), 123}}, {executable});
    auto state = ScriptRunnerTestAccess::state(execution, executable);
    require(state && !state->active && !state->runnable->autoDelete(), "queued state retains runnable");
    ScriptRunnerTestAccess::process(execution, state.data());
    require(state->queue.size() == 1 && executionCatalog.creates == 0,
            "inactive nonempty process does not pop");
    int completedSignals = 0;
    QObject::connect(&execution, &ScriptRunner::finished, &execution,
                     [&] { ++completedSignals; }, Qt::DirectConnection);
    int allSignals = 0;
    QObject::connect(&execution, &ScriptRunner::allFinished, &execution, [&] { ++allSignals; });
    state->active = true;
    ScriptRunnerTestAccess::process(execution, state.data());
    require(execution.counters() == qMakePair(qint64(1), qint64(1)), "processed counters");
    require(completedSignals == 1 && !state->active && state->queue.empty(), "completion then idle");
    require(executionCatalog.last->calls == QStringList({"response", "parameter", "event", "execute"}),
            "native virtual dispatch order");
    require(executionCatalog.last->response == response && executionCatalog.last->event.field28 == 123,
            "shared response and event cache survive queue");
    require(state->parallelism == 2, "instance concurrency property captured");
    execution.checkFinished();
    execution.checkFinished();
    QCoreApplication::sendPostedEvents(&execution, QEvent::MetaCall);
    require(allSignals == 1, "allFinished CAS emits only once");

    state->lastActivity = QDateTime::currentMSecsSinceEpoch() - 60000;
    execution.collectIdle();
    require(ScriptRunnerTestAccess::stateCount(execution, executable.toString()) == 0,
            "all idle states and count removed");
    ScriptRunnerTestAccess::idleKey(execution, "orphan");
    execution.collectIdle();
    require(ScriptRunnerTestAccess::hasIdleKey(execution, "orphan"), "empty range retains idle key");

    // Exercise real QThreadPool start with the inert fixture implementation.
    ScriptRunner pooled(executionCatalog, 0);
    pooled.enqueue({{}, {}, Event{8, {}, 0}}, {executable});
    pooled.start();
    require(ScriptRunnerTestAccess::wait(pooled), "offline pool completes within fixture limit");
    require(pooled.counters() == qMakePair(qint64(1), qint64(1)), "start drains mode0 queue");

    response->statusCode = 200;
    response->socketError = -7;
    response->request.setAttribute(QNetworkRequest::Attribute(10), QByteArray("GET"));
    response->request.setAttribute(QNetworkRequest::Attribute(1012), QVariant::fromValue(quint64(99)));
    response->request.setAttribute(QNetworkRequest::Attribute(1010), -1);
    response->request.setAttribute(QNetworkRequest::Attribute(1011), -2);
    require(describeScriptResponse(response).endsWith("errorDetails:'-7', origin:99, session:-1, flags:-2}"),
            "diagnostics include socket error and native signed arguments");
    auto vector = QSharedPointer<KeyValueInjectionVector>::create(QByteArray("name"), QByteArray("value"));
    auto parameter = QSharedPointer<HeaderParameterInjection>::create(vector, QString("name"), QString("value"));
    require(describeScriptParameter(parameter).startsWith("{name: 'name', value: 'value', type: 'Header'"),
            "confirmed native slots: name/value/kind");
    require(describeScriptWork({{}, {}, Event{0, {}, 0}}) ==
            "{request:null, parameter:null, event:{type: 0, isValid:0, args:''}}", "null work diagnostic");
    return 0;
}
