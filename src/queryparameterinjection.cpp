#include "parameterinjection.h"
#include <QDebug>
#include <QLoggingCategory>
#include <QUrl>

// gui.exe:0x1400AA790. Warning only; mutation continues on failed conversion.
QNetworkRequest QueryParameterInjection::applyVariant(const QVariant &injection, QNetworkRequest base)
{
    if (!injection.canConvert<QString>()) {
        const QLoggingCategory category("ParameterInjection.QueryParameterInjection");
        if (category.isWarningEnabled()) {
            QMessageLogger(nullptr, 0, nullptr, category.categoryName()).warning().noquote()
                << "Injection is not a string; injection:" << injection << "; base request:" << base.url().toString();
        }
    }
    const QString str = injection.toString();
    QUrl url = base.url();
    url.setQuery(str, QUrl::TolerantMode);
    base.setUrl(url);
    return base;
}
