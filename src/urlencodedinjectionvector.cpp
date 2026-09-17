#include "urlencodedinjectionvector.h"

#include <QMutexLocker>
#include <QUrlQuery>

UrlEncodedInjectionVector::UrlEncodedInjectionVector(const QueryItems &items,
                                                     qint32 selectedIndex)
    : m_items(items), m_selectedIndex(selectedIndex)
{
    // gui.exe:0x140113037: QList copy and selected index, empty encoder list.
}

bool UrlEncodedInjectionVector::isValid() const
{
    // gui.exe:0x1400AA620. Preserve the full QList length, not a qint32 cast.
    return !m_items.isEmpty() && m_selectedIndex >= 0
           && m_selectedIndex < m_items.size();
}

qint32 UrlEncodedInjectionVector::supportedFlagsRaw() const
{
    return 63; // gui.exe:0x1400AA640
}

QVariant UrlEncodedInjectionVector::apply(qint32 flags, const QString &value,
                                         const QString &name)
{
    // gui.exe:0x1400AAB80. v27/v28/v29 is a local, shared QList copy.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    if (!isValid())
        return {};
    QueryItems items = m_items;
    QString transformed;
    bool valueModified = false;
    if (flags & 1) {
        transformed = QString::fromUtf8(applyTransforms(value.toUtf8()));
        if (flags & 16)
            transformed = value;
        if (flags & 32) {
            items[m_selectedIndex].second = QStringLiteral("_Decoded_Place_");
        } else {
            transformed.replace(QLatin1Char('+'), QStringLiteral("%2B"));
            items[m_selectedIndex].second = transformed;
        }
        valueModified = true;
    }
    if (flags & 2) {
        items[m_selectedIndex].second = QString(); // native 0x1400AAD5F
        valueModified = true;
    }
    if (flags & 4) {
        items[m_selectedIndex].first = name;
        items[m_selectedIndex].first.replace(QLatin1Char('+'), QStringLiteral("%2B"));
    } else if (flags & 8) {
        items.removeAt(m_selectedIndex);
    } else if (!valueModified) {
        return {};
    }
    QUrlQuery query;
    query.setQueryItems(items);
    QString result = query.toString(QUrl::ComponentFormattingOptions::fromInt(32505856));
    result.replace(QStringLiteral("_Decoded_Place_"), transformed);
    return QVariant(result);
}

QVariant UrlEncodedInjectionVector::apply(qint32 flags, const QByteArray &value,
                                         const QString &name)
{
    return apply(flags, QString::fromUtf8(value), name); // gui.exe:0x1400AA710
}

QVariant UrlEncodedInjectionVector::apply(qint32 flags, qint32 value,
                                         const QString &name)
{
    return apply(flags, QString::number(value, 10), name); // gui.exe:0x1400AA690
}
