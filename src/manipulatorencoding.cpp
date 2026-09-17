#include "manipulator.h"
#include "base64encoding.h"
#include <QMutexLocker>

// gui.exe:0x140113920. Permissive native heuristic; no strict decoder added.
void Manipulator::detectBase64(const ParameterInjectionPtr &parameter)
{
    static const QRegularExpression nonPrintable(QStringLiteral("[^ -~]+"));
    static const QRegularExpression alphabet(QStringLiteral("^[a-zA-Z0-9+/=]+$"));
    const QString value = parameter->value(QString(), 0);
    if (value.size() < 4 && !value.contains(QLatin1Char('=')))
        return;
    if (!alphabet.match(value).hasMatch())
        return;
    const QString decoded = QString::fromUtf8(QByteArray::fromBase64(value.toUtf8()));
    if (nonPrintable.match(decoded).hasMatch())
        return;
    auto encoding = QSharedPointer<Base64Encoding>::create();
    QMutexLocker lock(&parameter->m_vector->m_transformMutex);
    parameter->m_vector->field10.append(encoding);
}

// gui.exe:0x140110BD0. Full labels verified by bytes at0x1402d84a0/8.
QString Manipulator::serializationType(const ParameterInjectionPtr &parameter)
{
    const QString value = parameter->value(QString(), 0);
    if (value.size() < 10)
        return QString();
    if (value.startsWith(QLatin1Char('{')))
        return QStringLiteral("JSON");
    if (value.mid(0, 2).toLower().startsWith(QStringLiteral("o:")))
        return QStringLiteral("PHP");
    if (!value.startsWith(QStringLiteral("rO0"), Qt::CaseSensitive))
        return QString();
    auto encoding = QSharedPointer<Base64Encoding>::create();
    QMutexLocker lock(&parameter->m_vector->m_transformMutex);
    parameter->m_vector->field10.append(encoding);
    return QStringLiteral("JAVA");
}
