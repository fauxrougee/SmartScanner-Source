#include "manipulator.h"
#include "parameterinjection.h"
#include "keyvalueinjectionvector.h"
#include "custominjectionvector.h"
#include "parameterexclusion.h"
#include "httpclient.h"
#include <QLoggingCategory>
#include <QMessageLogger>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QSharedPointer>
#include <QStringList>
#include <QUrl>


namespace {

// gui.exe:0x140110510 builds a copy of the original url text and rewrites
// each matched capture to the literal marker.  Cached statics mirror the
// function-local lazily-initialized QRegularExpression objects.
QString pathSegmentMarker(const QString &segment)
{
    static const QRegularExpression digitsExpression(QStringLiteral("^\\d+$"));
    static const QRegularExpression wordsExpression(
        QStringLiteral("^(blog|module|news|article)$"),
        QRegularExpression::CaseInsensitiveOption);

    if (segment.isEmpty()) {
        return QString();
    }
    if (digitsExpression.match(segment).hasMatch()) {
        return QStringLiteral("d");
    }
    if (wordsExpression.match(segment).hasMatch()) {
        return segment.toLower();
    }
    return QStringLiteral("w");
}

} // namespace

// gui.exe:0x14013ED60
static bool responseHasAttributeAllBits(const NetworkResponsePtr &reply, int mask)
{
    if (!reply) {
        return false;
    }
    const int value = reply->request.attribute(
        static_cast<QNetworkRequest::Attribute>(1011)).toInt();
    if (mask) {
        return (mask & value) == mask;
    }
    return value == 0;
}

// gui.exe:0x140110510 - pathSignature(a1=Manipulator, out=a2, url=a3)
QString Manipulator::pathSignature(const QUrl &url) const
{
    QString text = url.toString(QUrl::FormattingOptions(4294));
    text.replace(QStringLiteral("//"), QStringLiteral("/"), Qt::CaseSensitive);

    const qsizetype slashIndex = text.indexOf(QChar('/'), 9, Qt::CaseSensitive);
    QString prefix = text.left(slashIndex + 1);
    const QString remainder = text.right(text.size() - prefix.size());

    QString acc;
    const QStringList segments = remainder.split(QChar('/'), Qt::KeepEmptyParts,
                                                Qt::CaseSensitive);
    for (const QString &segment : segments) {
        if (segment.isEmpty()) {
            acc.append(QChar('/'));
            continue;
        }
        acc.append(pathSegmentMarker(segment));
        acc.append(QChar('/'));
    }

    acc = acc.left(acc.size() - 1);
    prefix.append(acc);
    return prefix;
}

// gui.exe:0x140112530 - pathParameters(reply)
void Manipulator::pathParameters(const NetworkResponsePtr &reply)
{
    if (!reply) {
        return;
    }
    if (!responseHasAttributeAllBits(reply, 505)) {
        return;
    }

    const QString urlText = reply->url.toString();
    QRegularExpressionMatchIterator it = m_pathExpression.globalMatch(urlText);

    if (it.hasNext()) {
        const QString signature = pathSignature(reply->url);
        if (m_pathSignatures.contains(signature)) {
            return; // gui.exe:0x140112605 QStringList::contains case-sensitive
        }
        m_pathSignatures.append(signature);
    }

    while (it.hasNext()) {
        const QRegularExpressionMatch match = it.next();
        const qsizetype capturedStart = match.capturedStart(0);
        const qsizetype capturedLength = match.capturedLength(0);

        QString pattern = urlText;
        pattern.remove(capturedStart, capturedLength);
        pattern.insert(capturedStart, QStringLiteral("_Inject_Here_"));

        auto vector = QSharedPointer<CustomInjectionVector>::create(pattern);
        auto injection = QSharedPointer<UrlParameterInjection>::create(
            vector, pattern, match.captured(0));

        const bool allowed = !exclusions
            || !parameterExcluded(*exclusions, *injection, urlText);
        if (allowed) {
            manipulate(injection, 32, reply);
        }
    }
}
