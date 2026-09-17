#pragma once

#include "scriptnativeports.h"

#include <QSharedPointer>

class NetworkManager;
class IssueDb;

// SOURCE RECONSTRUCTION NAME. GUI TestScript has the virtual slots recovered
// from 0x1402E1D98: response/parameter/event/options setters, abstract execute,
// name and id slots, maxInstances=1, defaultPriority=10 and empty hooks.
class TestScriptBase : public NativeScriptInstancePort {
public:
    explicit TestScriptBase(QString options = {});
    ~TestScriptBase() override = default;

    void setResponse(const NetworkResponsePtr &) override;
    void setParameter(const ParameterInjectionPtr &) override;
    void setEvent(const Event &) override;
    void setOptions(const QString &options);

    [[nodiscard]] quint32 maxInstances() const override;
    [[nodiscard]] quint32 defaultPriority() const override;
    [[nodiscard]] QList<quint64> hooks() const override;

    [[nodiscard]] virtual QString scriptName() const = 0;
    [[nodiscard]] virtual quint64 scriptId() const = 0;

    // gui.exe:0x140107280 wraps scriptId() with a retained NetworkManager owner
    // instead of preserving the base binding at +24.
    void bindNetworkManager(const QSharedPointer<NetworkManager> &manager);
    void bindIssueDb(IssueDb *db);

protected:
    [[nodiscard]] const QString &options() const noexcept { return m_options; }
    [[nodiscard]] const NetworkResponsePtr &response() const noexcept { return m_response; }
    [[nodiscard]] const ParameterInjectionPtr &parameter() const noexcept { return m_parameter; }
    [[nodiscard]] const Event &event() const noexcept { return m_event; }
    [[nodiscard]] IssueDb *issueDb() const noexcept { return m_issueDb; }

    // Helper to report issues - used by test implementations
    void reportIssue(const QString &issueName, const QString &issueId);

    struct NetworkContext {
        quint64 id = 0;
        QSharedPointer<NetworkManager> manager;
    };
    [[nodiscard]] const QSharedPointer<NetworkContext> &networkContext() const noexcept
    { return m_networkContext; }

private:
    QString m_options;                          // native +88
    NetworkResponsePtr m_response;              // native +112/+120
    QSharedPointer<NetworkContext> m_networkContext; // native +128/+136
    ParameterInjectionPtr m_parameter;          // native +144/+152
    Event m_event;                              // native +160/+168/+200
    IssueDb *m_issueDb = nullptr;               // native +216
    quint32 m_field208 = 0;                     // native +208, semantics unknown
};
