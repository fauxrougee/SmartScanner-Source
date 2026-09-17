#include "parameterinjection.h"
#include <QDebug>
#include <QLoggingCategory>
#include <QUrl>

// gui.exe:0x1400D74A0. Warning only; mutation continues on failed conversion.
QNetworkRequest UrlParameterInjection::applyVariant(const QVariant &injection, QNetworkRequest base)
{
    if (!injection.canConvert<QString>()) {
        const QLoggingCategory category("ParameterInjection.UrlParameterInjection");
        if (category.isWarningEnabled()) {
            QMessageLogger(nullptr, 0, nullptr, category.categoryName()).warning().noquote()
                << "Injection is not a string; injection:" << injection << "; base request:" << base.url().toString();
        }
    }
    base.setUrl(QUrl(injection.toString(), QUrl::TolerantMode));
    return base;
}
