#pragma once

#include <QBasicTimer>
#include <QDate>
#include <QDataStream>
#include <QObject>
#include <QString>
#include <QTime>

// Constructor/start/stop behavior from sms.exe Duration at 0x1400CDD80,
// 0x1400CDE60 and 0x1400CDEC0.
class Duration final : public QObject {
    Q_OBJECT
public:
    explicit Duration(QObject *parent = nullptr);

    void start();
    void stop();
    [[nodiscard]] QDate date() const noexcept { return m_date; }
    [[nodiscard]] int startTimeMilliseconds() const noexcept {
        return m_startTime.isNull() ? -1 : m_startTime.msecsSinceStartOfDay();
    }
    [[nodiscard]] quint64 elapsedSeconds() const noexcept { return m_elapsedSeconds; }
    [[nodiscard]] QString toDisplayString() const;

    // gui.exe:0x1400E2C45/51/5E and 0x1400E2001/0E/1B: seconds, QTime, QDate.
    friend QDataStream &operator<<(QDataStream &stream, const Duration &duration);
    friend QDataStream &operator>>(QDataStream &stream, Duration &duration);

protected:
    void timerEvent(QTimerEvent *event) override;

private:
    QBasicTimer m_timer;
    quint64 m_elapsedSeconds = 0;
    QTime m_startTime;
    QDate m_date;
};
