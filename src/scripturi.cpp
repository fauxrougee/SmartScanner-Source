// gui.exe:0x14010B800/0x1401067C0/0x140105920/0x14010C6C0.
#include "scripturi.h"

#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QStringList>

QList<quint64> ScriptURI::splitTriggerMask(quint64 mask)
{
    QList<quint64> result;
    for (int bit = 0; bit <= 36; ++bit) {
        const quint64 element = (quint64(1) << bit);
        if ((mask & element) == element)
            result.append(element);
    }
    return result;
}

void ScriptURI::decodeOptions(QString &text)
{
    text.replace(QStringLiteral("%2C"), QStringLiteral(","), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%3D"), QStringLiteral("="), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%3B"), QStringLiteral(";"), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%40"), QStringLiteral("@"), Qt::CaseInsensitive);
    text.replace(QStringLiteral("+"), QStringLiteral(" "), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%20"), QStringLiteral(" "), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%2F"), QStringLiteral("/"), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%23"), QStringLiteral("#"), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%3F"), QStringLiteral("?"), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%3A"), QStringLiteral(":"), Qt::CaseInsensitive);
    text.replace(QStringLiteral("%25"), QStringLiteral("%"), Qt::CaseInsensitive);
}

void ScriptURI::parse(const QString &text)
{
    name = text.trimmed();

    const qsizetype at = name.indexOf(QLatin1Char('@'), 0, Qt::CaseSensitive);
    if (at < 0) {
        name = name.toLower();
        return;
    }

    const QString tail = name.mid(at + 1, -1);
    name = name.left(at).toLower();

    static const QRegularExpression triggersRe(
        QStringLiteral("(?:triggers|r)=([^\\s;]+)"), QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression optionsRe(
        QStringLiteral("(?:options|o)=([^\\s;]+)"), QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression priorityRe(
        QStringLiteral("(?:priority|p)=([^\\s;]+)"), QRegularExpression::CaseInsensitiveOption);

    const QRegularExpressionMatch triggersMatch = triggersRe.match(tail);
    if (triggersMatch.hasMatch()) {
        const QStringList parts = triggersMatch.captured(1).split(
            QLatin1Char(','), Qt::SkipEmptyParts);
        for (const QString &part : parts)
            triggers.append(splitTriggerMask(part.toULongLong(nullptr, 10)));
    }

    const QRegularExpressionMatch optionsMatch = optionsRe.match(tail);
    if (optionsMatch.hasMatch()) {
        options = optionsMatch.captured(1);
        decodeOptions(options);
    }

    const QRegularExpressionMatch priorityMatch = priorityRe.match(tail);
    if (priorityMatch.hasMatch()) {
        bool ok = false;
        const int value = priorityMatch.captured(1).toInt(&ok, 10);
        if (!ok)
            priority = -1;
        else
            priority = value;
    }
}

QString ScriptURI::toString() const
{
    QString extras;

    if (!options.isEmpty()) {
        QString encoded = options;
        encoded.replace(QLatin1Char('='), QStringLiteral("%3D"), Qt::CaseSensitive);
        encoded.replace(QLatin1Char(';'), QStringLiteral("%3B"), Qt::CaseSensitive);
        encoded.replace(QLatin1Char('@'), QStringLiteral("%40"), Qt::CaseSensitive);
        encoded.replace(QLatin1Char(' '), QStringLiteral("%20"), Qt::CaseSensitive);
        extras.append(QStringLiteral("options=") + encoded);
    }

    if (!triggers.isEmpty()) {
        QStringList numbers;
        numbers.reserve(triggers.size());
        for (quint64 value : triggers)
            numbers.append(QString::number(value));
        if (!extras.isEmpty())
            extras.append(QLatin1Char(';'));
        extras.append(QStringLiteral("triggers=") + numbers.join(QLatin1Char(',')));
    }

    if (priority >= 0) {
        if (!extras.isEmpty())
            extras.append(QLatin1Char(';'));
        extras.append(QStringLiteral("priority=") + QString::number(priority));
    }

    if (extras.isEmpty())
        return name;
    return name + QLatin1Char('@') + extras;
}
