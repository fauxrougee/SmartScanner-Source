#pragma once

#include <QList>
#include <QString>
#include <QStringList>

#include <functional>

struct Custom404ProbeEvent final {
    quint64 id = 0;
    QString scope;
};

// gui.exe:0x14014E950 / 0x14014C2A0. `registrations` are its detector strings
// encoded as `scope::id`; events retain native numeric-key and input ordering.
[[nodiscard]] QList<Custom404ProbeEvent> custom404ScheduleProbeEvents(
    const QStringList &registrations, int threshold,
    const std::function<bool(const QString &, quint64)> &matches);
