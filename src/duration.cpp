#include "duration.h"

#include <QTime>
#include <QTimerEvent>

Duration::Duration(QObject *parent) : QObject(parent) {}

void Duration::start() {
    // Native check: only assign the start time if its field still contains -1.
    if (m_startTime.isNull())
        m_startTime = QTime::currentTime();
    m_date = QDate::currentDate();
    m_timer.start(1000, this);
}

void Duration::stop() {
    m_timer.stop();
}

QDataStream &operator<<(QDataStream &stream, const Duration &duration)
{
    // gui.exe:0x1400E2C45/51/5E imports qint64, QTime and QDate operators.
    stream << static_cast<qint64>(duration.m_elapsedSeconds)
           << duration.m_startTime << duration.m_date;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, Duration &duration)
{
    // gui.exe:0x1400E2001/0E/1B: restore fields without starting the timer.
    qint64 seconds = 0;
    stream >> seconds;
    duration.m_elapsedSeconds = static_cast<quint64>(seconds);
    stream >> duration.m_startTime >> duration.m_date;
    return stream;
}

void Duration::timerEvent(QTimerEvent *event)
{
    Q_UNUSED(event)
    // gui.exe:0x1400EAC00 increments the 64-bit seconds field for each
    // timer event. Duration owns no other timer in the recovered layout.
    ++m_elapsedSeconds;
}

QString Duration::toDisplayString() const
{
    // gui.exe:0x1400EAC10. The unit suffixes are U+2032 (prime) and U+2033
    // (double prime), not the provisional HH:mm:ss representation.
    const quint64 hoursTotal = m_elapsedSeconds / 60 / 60;
    const quint64 days = hoursTotal / 24;
    const quint64 hours = hoursTotal % 24;
    const quint64 minutes = m_elapsedSeconds / 60 % 60;
    const quint64 seconds = m_elapsedSeconds % 60;
    if (hoursTotal >= 24)
        return QStringLiteral("%1d %2h %3\u2032 %4\u2033")
            .arg(days).arg(hours).arg(minutes).arg(seconds);
    if (hours)
        return QStringLiteral("%1h %2\u2032 %3\u2033").arg(hours).arg(minutes).arg(seconds);
    if (minutes)
        return QStringLiteral("%1\u2032 %2\u2033").arg(minutes).arg(seconds);
    if (!seconds)
        return QStringLiteral("0");
    return QStringLiteral("%1\u2033").arg(seconds);
}
