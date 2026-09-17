#include "idordetector.h"
#include <QRegularExpression>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

namespace {

const QStringList sensitiveParams = {
    QStringLiteral("id"),
    QStringLiteral("user_id"),
    QStringLiteral("userId"),
    QStringLiteral("uid"),
    QStringLiteral("account_id"),
    QStringLiteral("accountId"),
    QStringLiteral("account"),
    QStringLiteral("profile_id"),
    QStringLiteral("profileId"),
    QStringLiteral("profile"),
    QStringLiteral("doc_id"),
    QStringLiteral("docId"),
    QStringLiteral("document_id"),
    QStringLiteral("documentId"),
    QStringLiteral("file_id"),
    QStringLiteral("fileId"),
    QStringLiteral("order_id"),
    QStringLiteral("orderId"),
    QStringLiteral("invoice_id"),
    QStringLiteral("invoiceId"),
    QStringLiteral("transaction_id"),
    QStringLiteral("transactionId"),
    QStringLiteral("record_id"),
    QStringLiteral("recordId"),
    QStringLiteral("item_id"),
    QStringLiteral("itemId"),
    QStringLiteral("product_id"),
    QStringLiteral("productId"),
    QStringLiteral("customer_id"),
    QStringLiteral("customerId"),
    QStringLiteral("client_id"),
    QStringLiteral("clientId"),
    QStringLiteral("member_id"),
    QStringLiteral("memberId"),
    QStringLiteral("employee_id"),
    QStringLiteral("employeeId"),
    QStringLiteral("staff_id"),
    QStringLiteral("staffId"),
    QStringLiteral("tenant_id"),
    QStringLiteral("tenantId"),
    QStringLiteral("org_id"),
    QStringLiteral("orgId"),
    QStringLiteral("organization_id"),
    QStringLiteral("organizationId"),
    QStringLiteral("company_id"),
    QStringLiteral("companyId"),
    QStringLiteral("group_id"),
    QStringLiteral("groupId"),
    QStringLiteral("team_id"),
    QStringLiteral("teamId"),
    QStringLiteral("project_id"),
    QStringLiteral("projectId"),
    QStringLiteral("workspace_id"),
    QStringLiteral("workspaceId"),
    QStringLiteral("folder_id"),
    QStringLiteral("folderId"),
    QStringLiteral("message_id"),
    QStringLiteral("messageId"),
    QStringLiteral("comment_id"),
    QStringLiteral("commentId"),
    QStringLiteral("post_id"),
    QStringLiteral("postId"),
    QStringLiteral("article_id"),
    QStringLiteral("articleId"),
    QStringLiteral("page_id"),
    QStringLiteral("pageId"),
    QStringLiteral("report_id"),
    QStringLiteral("reportId"),
    QStringLiteral("ticket_id"),
    QStringLiteral("ticketId"),
    QStringLiteral("case_id"),
    QStringLiteral("caseId"),
    QStringLiteral("issue_id"),
    QStringLiteral("issueId"),
    QStringLiteral("request_id"),
    QStringLiteral("requestId"),
    QStringLiteral("session_id"),
    QStringLiteral("sessionId"),
    QStringLiteral("token"),
    QStringLiteral("key"),
    QStringLiteral("secret"),
    QStringLiteral("api_key"),
    QStringLiteral("apiKey"),
    QStringLiteral("access_token"),
    QStringLiteral("accessToken"),
    QStringLiteral("refresh_token"),
    QStringLiteral("refreshToken"),
    QStringLiteral("auth_token"),
    QStringLiteral("authToken"),
    QStringLiteral("authorization"),
    QStringLiteral("password"),
    QStringLiteral("passwd"),
    QStringLiteral("pwd"),
    QStringLiteral("email"),
    QStringLiteral("username"),
    QStringLiteral("phone"),
    QStringLiteral("mobile"),
    QStringLiteral("ssn"),
    QStringLiteral("credit_card"),
    QStringLiteral("creditCard"),
    QStringLiteral("card_number"),
    QStringLiteral("cardNumber")
};

const QStringList pathIdPatterns = {
    QStringLiteral("/users/(\\d+)"),
    QStringLiteral("/user/(\\d+)"),
    QStringLiteral("/accounts/(\\d+)"),
    QStringLiteral("/account/(\\d+)"),
    QStringLiteral("/profiles/(\\d+)"),
    QStringLiteral("/profile/(\\d+)"),
    QStringLiteral("/documents/(\\d+)"),
    QStringLiteral("/document/(\\d+)"),
    QStringLiteral("/files/(\\d+)"),
    QStringLiteral("/file/(\\d+)"),
    QStringLiteral("/orders/(\\d+)"),
    QStringLiteral("/order/(\\d+)"),
    QStringLiteral("/invoices/(\\d+)"),
    QStringLiteral("/invoice/(\\d+)"),
    QStringLiteral("/api/v\\d+/[^/]+/(\\d+)"),
    QStringLiteral("/api/[^/]+/(\\d+)")
};

bool isSensitiveParameter(const QString &param) {
    QString lower = param.toLower();
    for (const QString &sensitive : sensitiveParams) {
        if (lower == sensitive.toLower()) {
            return true;
        }
    }
    return false;
}

bool isNumericId(const QString &value) {
    bool ok;
    value.toLongLong(&ok);
    return ok && !value.isEmpty();
}

bool isUuid(const QString &value) {
    QRegularExpression uuidRe(QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
                              QRegularExpression::CaseInsensitiveOption);
    return uuidRe.match(value).hasMatch();
}

bool isBase64Id(const QString &value) {
    QRegularExpression b64Re(QStringLiteral("^[A-Za-z0-9+/]{10,}={0,2}$"));
    return b64Re.match(value).hasMatch();
}

bool isHashLikeId(const QString &value) {
    QRegularExpression hashRe(QStringLiteral("^[a-f0-9]{32,64}$"),
                              QRegularExpression::CaseInsensitiveOption);
    return hashRe.match(value).hasMatch();
}

} // anonymous namespace


QList<IdorDetector::IdorCandidate> IdorDetector::analyze(const QUrl &url) const
{
    QList<IdorCandidate> candidates;

    QUrlQuery query(url);
    const auto items = query.queryItems();
    for (const auto &item : items) {
        const QString &param = item.first;
        const QString &value = item.second;

        if (isSensitiveParameter(param)) {
            IdorCandidate c;
            c.parameter = param;
            c.value = value;
            c.location = QStringLiteral("query");

            if (isNumericId(value)) {
                c.type = IdorType::PredictableId;
                c.likelihood = 80;
            } else if (isUuid(value)) {
                c.type = IdorType::DirectObjectReference;
                c.likelihood = 40;
            } else if (isBase64Id(value)) {
                c.type = IdorType::DirectObjectReference;
                c.likelihood = 60;
            } else {
                c.type = IdorType::DirectObjectReference;
                c.likelihood = 30;
            }

            candidates.append(c);
        }
    }

    QString path = url.path();
    for (const QString &pattern : pathIdPatterns) {
        QRegularExpression re(pattern, QRegularExpression::CaseInsensitiveOption);
        QRegularExpressionMatch match = re.match(path);
        if (match.hasMatch()) {
            IdorCandidate c;
            c.parameter = QStringLiteral("path_id");
            c.value = match.captured(1);
            c.location = QStringLiteral("path");
            c.type = IdorType::PredictableId;
            c.likelihood = 75;
            candidates.append(c);
        }
    }

    return candidates;
}

QList<IdorDetector::IdorCandidate> IdorDetector::analyzeBody(const QString &requestBody,
                                                              const QString &contentType) const
{
    QList<IdorCandidate> candidates;

    if (contentType.contains(QStringLiteral("application/json"))) {
        QJsonDocument doc = QJsonDocument::fromJson(requestBody.toUtf8());
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            for (auto it = obj.begin(); it != obj.end(); ++it) {
                if (isSensitiveParameter(it.key())) {
                    IdorCandidate c;
                    c.parameter = it.key();
                    c.value = it.value().toVariant().toString();
                    c.location = QStringLiteral("body");

                    if (it.value().isDouble() || isNumericId(c.value)) {
                        c.type = IdorType::PredictableId;
                        c.likelihood = 80;
                    } else {
                        c.type = IdorType::DirectObjectReference;
                        c.likelihood = 50;
                    }

                    candidates.append(c);
                }
            }
        }
    } else if (contentType.contains(QStringLiteral("application/x-www-form-urlencoded"))) {
        QUrlQuery query(requestBody);
        const auto items = query.queryItems();
        for (const auto &item : items) {
            if (isSensitiveParameter(item.first)) {
                IdorCandidate c;
                c.parameter = item.first;
                c.value = item.second;
                c.location = QStringLiteral("body");

                if (isNumericId(item.second)) {
                    c.type = IdorType::PredictableId;
                    c.likelihood = 80;
                } else {
                    c.type = IdorType::DirectObjectReference;
                    c.likelihood = 50;
                }

                candidates.append(c);
            }
        }
    }

    return candidates;
}

IdorDetector::IdorType IdorDetector::detect(const QString &response1, const QString &response2) const
{
    if (response1.isEmpty() || response2.isEmpty()) {
        return IdorType::None;
    }

    if (response1 != response2 && response2.length() > 100) {
        return IdorType::DirectObjectReference;
    }

    return IdorType::None;
}

bool IdorDetector::isVulnerable(const QString &response1, const QString &response2) const
{
    return detect(response1, response2) != IdorType::None;
}

QStringList IdorDetector::getSensitiveParameters()
{
    return sensitiveParams;
}

QStringList IdorDetector::getNumericIdPayloads(int originalId)
{
    QStringList payloads;

    payloads << QString::number(originalId - 1);
    payloads << QString::number(originalId + 1);
    payloads << QString::number(originalId - 10);
    payloads << QString::number(originalId + 10);
    payloads << QStringLiteral("1");
    payloads << QStringLiteral("0");
    payloads << QStringLiteral("-1");
    payloads << QStringLiteral("999999");
    payloads << QStringLiteral("2147483647");
    payloads << QStringLiteral("-2147483648");
    payloads << QString::number(originalId) + QStringLiteral("'");
    payloads << QString::number(originalId) + QStringLiteral(" OR 1=1");
    payloads << QStringLiteral("admin");
    payloads << QStringLiteral("root");
    payloads << QStringLiteral("null");
    payloads << QStringLiteral("undefined");

    return payloads;
}

QStringList IdorDetector::getUuidPayloads(const QString &originalUuid)
{
    Q_UNUSED(originalUuid)

    QStringList payloads;

    payloads << QStringLiteral("00000000-0000-0000-0000-000000000000");
    payloads << QStringLiteral("00000000-0000-0000-0000-000000000001");
    payloads << QStringLiteral("ffffffff-ffff-ffff-ffff-ffffffffffff");
    payloads << QUuid::createUuid().toString(QUuid::WithoutBraces);
    payloads << QStringLiteral("admin");
    payloads << QStringLiteral("null");
    payloads << QStringLiteral("undefined");
    payloads << QStringLiteral("' OR '1'='1");

    return payloads;
}

int IdorDetector::severityLevel(IdorType type)
{
    switch (type) {
    case IdorType::DirectObjectReference:
        return 3; // High
    case IdorType::PredictableId:
        return 3; // High
    case IdorType::ParameterManipulation:
        return 2; // Medium
    case IdorType::MassAssignment:
        return 3; // High
    case IdorType::PathTraversal:
        return 4; // Critical
    default:
        return 0;
    }
}
