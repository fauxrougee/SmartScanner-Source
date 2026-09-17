#include "custom404urlhistory.h"

#include "custom404urlscope.h"
#include "urlnormalizer.h"

#include <QMutexLocker>

bool Custom404UrlHistory::accepts(const QUrl &url, int sequenceKey)
{
    // gui.exe:0x14014D730. sub_14014B910 selects/creates the sequence at
    // detector+0x38 for the native integer argument before this exact loop.
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    const QString canonical = UrlNormalizer::canonical(url, 14);
    QList<QUrl> &urls = m_urlsBySequence[sequenceKey];

    for (const QUrl &previous : urls) {
        if (UrlNormalizer::canonical(previous, 14) == canonical)
            return true;
        if (!custom404SamePathRoot(previous, url, true))
            return false;
    }

    urls.append(url);
    return true;
}

qsizetype Custom404UrlHistory::urlCount(int sequenceKey) const
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    return m_urlsBySequence.value(sequenceKey).size();
}
