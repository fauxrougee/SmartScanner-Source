#pragma once

#include "custom404probescheduler.h"

#include <QList>
#include <QStringList>
#include <QUrl>

struct Custom404ScheduledProbeEvent final {
    int threshold = 0;
    Custom404ProbeEvent event;
};

// gui.exe:0x14014E1A0. The numeric response identity originates in a separate
// native helper and is supplied explicitly here.
[[nodiscard]] QString custom404ProbeRegistration(const QUrl &url,
                                                  quint64 responseIdentity);
[[nodiscard]] QList<Custom404ScheduledProbeEvent> custom404ScheduleProbePlan(
    const QStringList &registrations, const QUrl &responseUrl);
