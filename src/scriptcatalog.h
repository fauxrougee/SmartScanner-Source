#pragma once

#include "scriptnativeports.h"
#include "scriptfactory.h"

#include <QSharedPointer>

class NetworkManager;
class IssueDb;

// Production implementation of NativeScriptCatalogPort using ScriptFactory.
class ScriptCatalog final : public NativeScriptCatalogPort {
public:
    ScriptCatalog();
    ~ScriptCatalog() override = default;

    ScriptURI resolve(ScriptURI descriptor) override;
    QSharedPointer<NativeScriptInstancePort> create(const ScriptURI &descriptor) override;

    void setNetworkManager(const QSharedPointer<NetworkManager> &manager);
    void setIssueDb(IssueDb *db);
    ScriptFactory &factory() { return m_factory; }

private:
    void registerBuiltinTests();
    ScriptFactory m_factory;
    QSharedPointer<NetworkManager> m_networkManager;
    IssueDb *m_issueDb = nullptr;
};
