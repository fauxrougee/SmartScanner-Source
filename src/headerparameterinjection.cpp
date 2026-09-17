#include "parameterinjection.h"
#include "keyvalueinjectionvector.h"
#include <QDebug>
#include <QLoggingCategory>
#include <QUrl>

// gui.exe:0x140087D70. Warning only; mutation continues on failed conversion.
QNetworkRequest HeaderParameterInjection::applyVariant(const QVariant &injection, QNetworkRequest base)
{
    if (!injection.canConvert<NativeBytePair>()) {
        const QLoggingCategory category("ParameterInjection.HeaderParameterInjection");
        if (category.isWarningEnabled()) {
            QMessageLogger(nullptr, 0, nullptr, category.categoryName()).warning().noquote()
                << "Injection is not a key value; injection:" << injection << "; base request:" << base.url().toString();
        }
    }
    const NativeBytePair pair = qvariant_cast<NativeBytePair>(injection);
    base.setRawHeader(pair.first, pair.second);
    auto headers = qvariant_cast<QList<QByteArray>>(base.attribute(QNetworkRequest::Attribute(1015)));
    headers.append(pair.first);
    base.setAttribute(QNetworkRequest::Attribute(1015), QVariant::fromValue(headers));
    return base;
}
