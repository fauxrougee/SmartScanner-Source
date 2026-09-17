#pragma once
#include "injectionvector.h"

// Native RTTI Base64Encoding; first two EncodingInterface operations recovered.
// Native +8 kind1, +16 mutex initialized; these methods do not acquire it.
class Base64Encoding final : public NativeByteTransform {
public:
    QByteArray transform(const QByteArray &) override;
    QByteArray decode(const QByteArray &) override;
private:
    qint32 m_kind = 1;
    QMutex m_mutex;
};
