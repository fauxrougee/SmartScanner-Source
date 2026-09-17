#include "scriptfactory.h"

#include <QCoreApplication>

namespace {
void require(bool condition, const char *message)
{
    if (!condition)
        qFatal("%s", message);
}

class FixtureInstance final : public NativeScriptInstancePort {
public:
    void setResponse(const NetworkResponsePtr &) override {}
    void setParameter(const ParameterInjectionPtr &) override {}
    void setEvent(const Event &) override {}
    void execute() override {}
    quint32 maxInstances() const override { return 1; }
    quint32 defaultPriority() const override { return 10; }
    QList<quint64> hooks() const override { return {16}; }
};

class FixtureBinder final : public ScriptFactoryDependencyBinder {
public:
    void bind(const QSharedPointer<NativeScriptInstancePort> &) const override { ++calls; }
    mutable int calls = 0;
};
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    FixtureBinder binder;
    ScriptFactory factory(binder);
    require(!factory.create(ScriptURI(QStringLiteral("missing"))), "missing create is null");
    require(factory.resolve(ScriptURI(QStringLiteral("missing"))).name == QStringLiteral("missing"),
            "missing resolve preserves descriptor");

    ScriptFactoryEntry direct;
    direct.name = QStringLiteral("direct");
    direct.triggers = {8, 8};
    direct.priority = 5;
    direct.make = [](const QString &) { return QSharedPointer<FixtureInstance>::create(); };
    require(factory.registerEntry(std::move(direct)), "register direct");
    require(factory.appendTriggers(QStringLiteral("direct"), {3, 2}), "append masks");
    ScriptURI directUri(QStringLiteral("direct"));
    const ScriptURI directResolved = factory.resolve(directUri);
    require(directResolved.triggers == QList<quint64>({8, 8, 1, 2, 2})
            && directResolved.priority == 5, "stored triggers, expanded masks and priority copied");
    require(binder.calls == 0, "stored hooks avoid lazy create");

    ScriptFactoryEntry lazy;
    lazy.name = QStringLiteral("lazy");
    lazy.priority = -1;
    lazy.make = [](const QString &) { return QSharedPointer<FixtureInstance>::create(); };
    require(factory.registerEntry(std::move(lazy)), "register lazy");
    const ScriptURI lazyResolved = factory.resolve(ScriptURI(QStringLiteral("lazy@options=x")));
    require(lazyResolved.triggers == QList<quint64>({16}) && lazyResolved.priority == 10,
            "lazy hooks and priority copied from instance");
    require(binder.calls == 1, "lazy resolution binds once");
    require(factory.idForName(QStringLiteral("DIRECT")) == ScriptFactory::keyForName(QStringLiteral("direct")),
            "name id lower-case lookup rehashes registered name");
    return 0;
}
