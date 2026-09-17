#pragma once

#include "filelist.h"
#include "networkmanager.h"

#include <QObject>

// Clean-room transcription of gui.exe Crawler.  Its constructor is
// 0x14010F4D0 and the dispatch slot is 0x14010F6B0.
class Crawler final : public QObject {
    Q_OBJECT
public:
    explicit Crawler(FileList *fileList, NetworkManager *networkManager,
                     QObject *parent = nullptr);

    // gui.exe:0x14010F6A0.
    [[nodiscard]] quint64 crawled() const noexcept { return m_crawled; }
    [[nodiscard]] quint64 scheduled() const noexcept { return m_scheduled; }

    // Reconstruction name for the native shared rule state. Its configuration
    // producer remains to be connected; this preserves ownership at dispatch.
    void setValueRules(const QSharedPointer<QList<HtmlFormValueRule>> &rules) {
        m_valueRules = rules;
    }

public slots:
    // gui.exe:0x14010F6B0.
    void start();

private:
    FileList *m_fileList = nullptr;
    NetworkManager *m_networkManager = nullptr;
    // Native offsets +0x30 and +0x38.  The former is a FileList cursor, not
    // the number of remaining entries; the latter counts non-cancelled
    // submissions, including entries already marked as submitted.
    quint64 m_scheduled = 0;
    quint64 m_crawled = 0;
    // gui.exe:0x14010F551/555: +0x40/+0x48 shared-pointer words.
    QSharedPointer<QList<HtmlFormValueRule>> m_valueRules;
};
