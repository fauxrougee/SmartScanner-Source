#pragma once

#include <QByteArray>
#include <QList>
#include <QRecursiveMutex>
#include <QUrl>

// gui.exe:0x14014D930 / 0x14014BD90. Retains only bodies that are not more
// than 90% similar to an already retained, URL-masked body.
class Custom404BodyHistory final {
public:
    [[nodiscard]] bool hasSimilar(const QByteArray &body, const QUrl &url) const;
    void retainIfDistinct(const QByteArray &body, const QUrl &url);
    [[nodiscard]] qsizetype count() const;

private:
    mutable QRecursiveMutex m_mutex;
    QList<QByteArray> m_bodies;
};
