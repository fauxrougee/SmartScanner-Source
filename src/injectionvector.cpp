#include "injectionvector.h"

#include <QMutexLocker>

// gui.exe:0x140086EF0. Native assumes non-null transform pointers and an empty
// list results in no iteration; the input is returned by move-construction.
QByteArray InjectionVector::applyTransforms(QByteArray input)
{
    const QMutexLocker<QMutex> lock(&m_transformMutex);
    for (auto it = field10.crbegin(); it != field10.crend(); ++it)
        input = (*it)->transform(input);
    return input;
}

// gui.exe:0x140086D50. Forward traversal of the distinct second virtual.
QByteArray InjectionVector::decodeTransforms(QByteArray input)
{
    const QMutexLocker<QMutex> lock(&m_transformMutex);
    for (auto it = field10.cbegin(); it != field10.cend(); ++it)
        input = (*it)->decode(input);
    return input;
}
