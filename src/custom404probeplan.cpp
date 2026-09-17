#include "custom404probeplan.h"

#include "custom404probethresholds.h"
#include "custom404urlscope.h"

namespace {

constexpr QUrl::ComponentFormattingOptions registrationUrlFormatting =
    static_cast<QUrl::ComponentFormattingOptions>(192);

void appendEvents(QList<Custom404ScheduledProbeEvent> &output, int threshold,
                  const QList<Custom404ProbeEvent> &events)
{
    for (const Custom404ProbeEvent &event : events)
        output.append({threshold, event});
}

} // namespace

QString custom404ProbeRegistration(const QUrl &url, quint64 responseIdentity)
{
    // gui.exe:0x14014E1FE through 0x14014E264.
    return url.toString(registrationUrlFormatting) + QStringLiteral("::")
        + QString::number(responseIdentity);
}

QList<Custom404ScheduledProbeEvent> custom404ScheduleProbePlan(
    const QStringList &registrations, const QUrl &responseUrl)
{
    // gui.exe:0x14014E2B2 - 0x14014E36A. The three scheduler invocations are
    // ordered 5, 10, 15 and can therefore emit duplicate scope/id pairs.
    const QString root = custom404PathRoot(responseUrl,
                                           custom404PathSlashCount(responseUrl));
    QList<Custom404ScheduledProbeEvent> output;
    appendEvents(output, 5, custom404ScheduleProbeEvents(
                               registrations, 5, [&root](const QString &scope, quint64) {
                                   return custom404ProbeMatchesPathRoot(scope, root);
                               }));
    appendEvents(output, 10, custom404ScheduleProbeEvents(
                                registrations, 10, [&responseUrl](const QString &scope, quint64) {
                                    return custom404ProbeMatchesHost(scope, responseUrl);
                                }));
    appendEvents(output, 15, custom404ScheduleProbeEvents(
                                registrations, 15, [](const QString &, quint64) {
                                    return custom404ProbeMatchesUnconditionally();
                                }));
    return output;
}
