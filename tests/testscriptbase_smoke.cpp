#include "testscriptbase.h"
#include "networkmanager.h"

#include <QCoreApplication>

namespace {
void require(bool condition, const char *message)
{
    if (!condition)
        qFatal("%s", message);
}

class FixtureScript final : public TestScriptBase {
public:
    using TestScriptBase::TestScriptBase;
    void execute() override { ++executions; }
    QString scriptName() const override { return QStringLiteral("fixture"); }
    quint64 scriptId() const override { return 77; }
    const QString &readOptions() const { return options(); }
    const NetworkResponsePtr &readResponse() const { return response(); }
    const ParameterInjectionPtr &readParameter() const { return parameter(); }
    const Event &readEvent() const { return event(); }
    const QSharedPointer<NetworkContext> &readNetworkContext() const { return networkContext(); }
    int executions = 0;
};
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    FixtureScript script(QStringLiteral("native-options"));
    require(script.readOptions() == QStringLiteral("native-options"), "options copied by ctor");
    require(script.maxInstances() == 1 && script.defaultPriority() == 10 && script.hooks().isEmpty(),
            "native default virtuals");
    Event event{16, QStringLiteral("event"), 0};
    script.setEvent(event);
    require(script.readEvent().type == 16 && script.readEvent().data.toString() == QStringLiteral("event"),
            "event retained by value");
    script.setOptions(QStringLiteral("changed"));
    require(script.readOptions() == QStringLiteral("changed"), "options setter");
    auto manager = QSharedPointer<NetworkManager>::create(QStringLiteral("fixture"));
    script.bindNetworkManager(manager);
    require(script.readNetworkContext() && script.readNetworkContext()->id == 77
            && script.readNetworkContext()->manager == manager, "network context retains id and manager");
    script.execute();
    require(script.executions == 1, "abstract execute implemented by derived script");
    return 0;
}
