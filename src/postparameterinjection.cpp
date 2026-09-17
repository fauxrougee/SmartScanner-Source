#include "parameterinjection.h"
#include <QDebug>
#include <QLoggingCategory>
#include <QUrl>

// gui.exe:0x1400FA680. Warning only; mutation continues on failed conversion.
QNetworkRequest PostParameterInjection::applyVariant(const QVariant &injection, QNetworkRequest base)
{
    if (!injection.canConvert<QByteArray>()) {
        const QLoggingCategory category("ParameterInjection.PostParameterInjection");
        if (category.isWarningEnabled()) {
            QMessageLogger(nullptr, 0, nullptr, category.categoryName()).warning().noquote()
                << "Injection is not byte array; injection:" << injection << "; base request:" << base.url().toString();
        }
    }
    const QByteArray bytes = injection.toByteArray();
    base.setHeader(QNetworkRequest::ContentLengthHeader, QVariant());
    // gui.exe:0x14013DE00
    base.setAttribute(QNetworkRequest::Attribute(1003), QVariant(bytes));
    return base;
}
