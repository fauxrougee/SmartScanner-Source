#include "parameterinjection.h"
#include <QNetworkCookie>
#include <QDebug>
#include <QLoggingCategory>
#include <QUrl>

// gui.exe:0x1400FA350. Warning only; mutation continues on failed conversion.
QNetworkRequest CookieParameterInjection::applyVariant(const QVariant &injection, QNetworkRequest base)
{
    if (!injection.canConvert<QList<QNetworkCookie>>()) {
        const QLoggingCategory category("ParameterInjection.CookieParameterInjection");
        if (category.isWarningEnabled()) {
            QMessageLogger(nullptr, 0, nullptr, category.categoryName()).warning().noquote()
                << "Injection is not a list of cookie; injection:" << injection << "; base request:" << base.url().toString();
        }
    }
    const auto cookies = qvariant_cast<QList<QNetworkCookie>>(injection);
    base.setHeader(QNetworkRequest::CookieHeader, QVariant::fromValue(cookies));
    auto headers = qvariant_cast<QList<QByteArray>>(base.attribute(QNetworkRequest::Attribute(1015)));
    headers.append(QByteArrayLiteral("Cookie"));
    base.setAttribute(QNetworkRequest::Attribute(1015), QVariant::fromValue(headers));
    return base;
}
