#include "custom404bodyhistory.h"

#include "custom404bodymasker.h"
#include "custom404similarity.h"

#include <QMutexLocker>

bool Custom404BodyHistory::hasSimilar(const QByteArray &body, const QUrl &url) const
{
    // gui.exe:0x14014D930 obtains 0x14014E3D0's masked body before taking the
    // detector mutex, then returns on the first score strictly above 90.0.
    const QByteArray masked = custom404MaskedBody(body, url);
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    for (const QByteArray &stored : m_bodies) {
        if (Custom404Similarity::score(masked, stored) > 90.0)
            return true;
    }
    return false;
}

void Custom404BodyHistory::retainIfDistinct(const QByteArray &body, const QUrl &url)
{
    // gui.exe:0x14014BD90 calls the preceding predicate first. Its append is
    // intentionally separate from that check, matching the native lock scope.
    if (hasSimilar(body, url))
        return;
    const QByteArray masked = custom404MaskedBody(body, url);
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    m_bodies.append(masked);
}

qsizetype Custom404BodyHistory::count() const
{
    const QMutexLocker<QRecursiveMutex> lock(&m_mutex);
    return m_bodies.size();
}
