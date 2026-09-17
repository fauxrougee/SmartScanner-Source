#pragma once

#include <QWebEngineView>

class MainWebView final : public QWebEngineView {
    Q_OBJECT
public:
    explicit MainWebView(QWidget *parent = nullptr);

    // gui.exe paths 0x14001CFE0 and 0x14001E640.
    bool handleDeepLinks(const QStringList &arguments);

protected:
    void closeEvent(QCloseEvent *event) override;
};
