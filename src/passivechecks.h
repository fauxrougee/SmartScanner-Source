#pragma once

#include "networkmanager.h"

#include <QString>

class IssueDb;

// Passive security checks that analyze HTTP responses without sending additional requests.
// These correspond to multiple native test scripts that run on scriptTriggerEvent8.
class PassiveChecks final
{
public:
    static void processErrorDetection(const NetworkManager::ResponsePointer &response,
                                      IssueDb *issueDb, const QString &genericIssueDataPath);

    static void processPassive(const NetworkManager::ResponsePointer &response,
                               IssueDb *issueDb, const QString &selection,
                               const QString &genericIssueDataPath);

    static void processSecretLeak(const NetworkManager::ResponsePointer &response,
                                  IssueDb *issueDb, const QString &genericIssueDataPath);

    static void processRobotsTxt(const NetworkManager::ResponsePointer &response,
                                 IssueDb *issueDb, const QString &genericIssueDataPath);

    static void processLoginPage(const NetworkManager::ResponsePointer &response,
                                 IssueDb *issueDb, const QString &genericIssueDataPath);

    static void processFingerprint(const NetworkManager::ResponsePointer &response,
                                   IssueDb *issueDb, const QString &genericIssueDataPath);

    static void processHttps(const NetworkManager::ResponsePointer &response,
                             IssueDb *issueDb, const QString &selection,
                             const QString &genericIssueDataPath);

    static void processHttpsRedirection(const NetworkManager::ResponsePointer &response,
                                        IssueDb *issueDb, const QString &genericIssueDataPath);

    static void processBrokenLink(const NetworkManager::ResponsePointer &response,
                                  IssueDb *issueDb, const QString &genericIssueDataPath);

    static void processTlsVersion(const NetworkManager::ResponsePointer &response,
                                  IssueDb *issueDb, const QString &genericIssueDataPath);
};
