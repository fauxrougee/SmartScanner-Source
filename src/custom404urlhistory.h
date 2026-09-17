#pragma once

#include <QHash>
#include <QList>
#include <QRecursiveMutex>
#include <QUrl>

// gui.exe:0x14014D730. This is the URL-history gate embedded in the
// stateful Custom404Detector. The native integer selects an independent URL
// sequence; its original semantic name is not recoverable.
class Custom404UrlHistory final {
public:
    [[nodiscard]] bool accepts(const QUrl &url, int sequenceKey);
    [[nodiscard]] qsizetype urlCount(int sequenceKey) const;

private:
    mutable QRecursiveMutex m_mutex;
    QHash<int, QList<QUrl>> m_urlsBySequence;
};
