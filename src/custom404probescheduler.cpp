#include "custom404probescheduler.h"

#include <QMap>

namespace {

QString registrationScope(const QString &registration)
{
    return registration.section(QStringLiteral("::"), 0, 0);
}

quint64 registrationId(const QString &registration)
{
    return registration.section(QStringLiteral("::"), 1, 1).toULongLong();
}

} // namespace

QList<Custom404ProbeEvent> custom404ScheduleProbeEvents(
    const QStringList &registrations, int threshold,
    const std::function<bool(const QString &, quint64)> &matches)
{
    // gui.exe:0x14014E950 builds a std::map keyed by the parsed unsigned
    // number, increments it for each matching registration, and walks that
    // map in key order. For every count meeting a3 it calls 0x14014C2A0,
    // which emits each registration with the same numeric suffix in the
    // source collection order.
    QMap<quint64, int> counts;
    for (const QString &registration : registrations) {
        const QString scope = registrationScope(registration);
        const quint64 id = registrationId(registration);
        if (matches(scope, id))
            ++counts[id];
    }

    QList<Custom404ProbeEvent> events;
    for (auto it = counts.cbegin(); it != counts.cend(); ++it) {
        if (it.value() < threshold)
            continue;
        for (const QString &registration : registrations) {
            if (registrationId(registration) == it.key())
                events.append({it.key(), registrationScope(registration)});
        }
    }
    return events;
}
