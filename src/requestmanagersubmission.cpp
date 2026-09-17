#include "requestmanager.h"

#include <QDebug>
#include <QList>
#include <QNetworkAccessManager>
#include <QNetworkCookie>
#include <QNetworkCookieJar>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSharedPointer>
#include <QUrl>

// sms.exe:0x140137020. Worker proposal adapted after native review.
// The source wrapper prepares a local copy; the native mutates its request argument.
bool RequestManager::submitPreparedRequest(const QNetworkRequest &request)
{
    const quint64 requestId = request
                                  .attribute(static_cast<QNetworkRequest::Attribute>(1002))
                                  .toULongLong();
    const quint64 previousActive = m_activeRequestCount;

    if (!requestId) {
        if (previousActive == 0 && m_allFinishedPending) {
            m_allFinishedPending = false;
            emit allFinished(); // sms.exe:0x14015FA90 (QMetaObject::activate, signal 1)
        }
        return false; // 0
    }

    ++m_activeRequestCount;
    m_lastRequestUrl = request.url();

    QNetworkRequest prepared(request);
    prepareRequest(prepared);

    QList<QNetworkCookie> savedCookies;
    QList<QNetworkCookie> injectedCookies;
    prepareCookies(prepared, savedCookies, injectedCookies);

    const QByteArray body = prepared
                                .attribute(static_cast<QNetworkRequest::Attribute>(1003))
                                .toByteArray();

    prepared.setAttribute(static_cast<QNetworkRequest::Attribute>(1001),
                         QDateTime::currentMSecsSinceEpoch());

    const QByteArray method = prepared
                                  .attribute(static_cast<QNetworkRequest::Attribute>(10))
                                  .toByteArray();

    QNetworkReply *reply = m_accessManager.sendCustomRequest(prepared, method, body);

    connect(reply, &QNetworkReply::metaDataChanged,
            this, &RequestManager::headerReceived);
    connect(reply, &QNetworkReply::readyRead,
            this, &RequestManager::readyReady);

    reply->setParent(nullptr);

    restoreCookies(savedCookies, injectedCookies);

    m_constructedAt = QDateTime::currentDateTime();

    QSharedPointer<QNetworkReply> guarded(reply, [](QNetworkReply *r) {
        if (r)
            r->deleteLater();
    });

    const quint64 replyId = reply->request()
                                .attribute(static_cast<QNetworkRequest::Attribute>(1002))
                                .toULongLong();

    if (!replyId) {
        if (m_logCategory.isWarningEnabled()) {
            qCWarning(m_logCategory).noquote().nospace() << "Request has no ID; reply:";
        }
        reply->setProperty("id", QVariant::fromValue(requestId));
    }

    m_replies.insert(requestId, guarded);

    return true; // 1
}
