#include "manipulator.h"
#include "parameterinjection.h"
#include "injectionvector.h"
#include <QLoggingCategory>
#include <QMessageLogger>
#include <QDebug>
#include <QMutexLocker>
#include <QNetworkReply>
#include <QRegularExpression>
#include <QSharedPointer>
#include <QVariant>

// Reconstruction of gui.exe:0x14010FF00 (ctor), 0x140113770 (scan),
// 0x140110F00 (manipulate). See decompiled/gui_execution_component_ctors_hexrays.c,
// decompiled/gui_manipulator_dispatch_hexrays.c and
// decompiled/gui_manipulator_common_wave10_hexrays.c.

Manipulator::Manipulator(QObject *parent)
    : QObject(parent)
{
    // ctor defaults per native init order.
    networkManager = nullptr;
    parameterCount = 0;
    vectorFlags = 31;
    // path expression: (?<=/|-)\d+(?=/|$|-) CaseInsensitive (option 1).
    m_pathExpression = QRegularExpression(
        QStringLiteral("(?<=/|-)\\d+(?=/|$|-)"),
        QRegularExpression::CaseInsensitiveOption);
    // JSON expression written verbatim from native literal.
    m_jsonExpression = QRegularExpression(
        QString::fromUtf8(R"native(([^"']\b)([a-zA-Z_$]+[0-9a-zA-Z_$]*[^"]):)native"),
        QRegularExpression::CaseInsensitiveOption);
    // DirCount field18[0]=1, [1]=7; field08=1; field30=15.
    m_headerConstraint.field18.insert(0, 1);
    m_headerConstraint.field18.insert(1, 7);
    m_headerConstraint.field08 = 1;
    m_headerConstraint.field30 = 15;
}

void Manipulator::scan(NetworkResponsePtr reply)
{
    if (!reply)
        return;

    if ((vectorFlags & 1u) && reply->url.hasQuery()) {
        const QUrlQuery urlQuery(reply->url);
        const QString packetString = reply->request
            .attribute(QNetworkRequest::Attribute(1003)).toString();
        const QUrlQuery packetQuery(packetString);
        const QList<QPair<QString, QString>> packetItems =
            packetQuery.queryItems(QUrl::PrettyDecoded);
        queryParameters(urlQuery, reply, false, packetItems);
    }
    if (vectorFlags & 2u)
        postParameters(reply);
    if (vectorFlags & 4u)
        cookieParameters(reply);
    if (vectorFlags & 8u)
        headerParameters(reply);
    if (vectorFlags & 16u)
        pathParameters(reply);
}

void Manipulator::manipulate(ParameterInjectionPtr param, quint64 eventType,
                             NetworkResponsePtr reply)
{
    if (param && param->isValid()) {
        ++parameterCount;
        detectBase64(param);
        const QString type = serializationType(param);
        if (!type.isNull()) {
            Event extra;
            extra.type = 0x200000000ULL;
            extra.data = QVariant(type);
            extra.field28 = 0;
            emit eventTriggered(extra, reply, param);
        }
        Event main;
        main.type = eventType;
        main.data = QVariant();
        main.field28 = 0;
        emit eventTriggered(main, reply, param);
    } else {
        QLoggingCategory category("scanner.manipulator");
        if (category.isWarningEnabled()) {
            QMessageLogger(nullptr, 0, nullptr, category.categoryName()).warning()
                << "Invalid Parameter: " << reply->url.toString();
        }
    }
}
