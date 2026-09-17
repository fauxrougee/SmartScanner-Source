#include "testscriptbase.h"

#include "networkmanager.h"
#include "issuedb.h"
#include "issue.h"
#include "issuetemplate.h"

#include <QCoreApplication>
#include <utility>

TestScriptBase::TestScriptBase(QString options)
    : m_options(std::move(options))
{
}

void TestScriptBase::setResponse(const NetworkResponsePtr &response)
{
    m_response = response;
}

void TestScriptBase::setParameter(const ParameterInjectionPtr &parameter)
{
    m_parameter = parameter;
}

void TestScriptBase::setEvent(const Event &event)
{
    m_event = event;
}

void TestScriptBase::setOptions(const QString &options)
{
    m_options = options;
}

quint32 TestScriptBase::maxInstances() const
{
    return 1;
}

quint32 TestScriptBase::defaultPriority() const
{
    return 10;
}

QList<quint64> TestScriptBase::hooks() const
{
    return {};
}

void TestScriptBase::bindNetworkManager(const QSharedPointer<NetworkManager> &manager)
{
    auto context = QSharedPointer<NetworkContext>::create();
    context->id = scriptId();
    context->manager = manager;
    m_networkContext = std::move(context);
}

void TestScriptBase::bindIssueDb(IssueDb *db)
{
    m_issueDb = db;
}

void TestScriptBase::reportIssue(const QString &issueName, const QString &issueId)
{
    if (!m_issueDb || !m_response)
        return;
    const QString genericIssues = QCoreApplication::applicationDirPath()
        + QStringLiteral("/assets/issues/generic-min.json");
    Issue issue;
    IssueTemplate::applyGeneric(&issue, issueName, genericIssues);
    issue.field30 = m_response->url;
    issue.field00 = issueId;
    m_issueDb->add(issue);
}
