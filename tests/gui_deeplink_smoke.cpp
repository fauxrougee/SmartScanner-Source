#include "mainwebview.h"
#include <QApplication>
#include <QStandardPaths>

int main(int argc, char **argv)
{
    QCoreApplication::setOrganizationName(QStringLiteral("SmartScannerReconstructionTests"));
    QCoreApplication::setApplicationName(QStringLiteral("gui_deeplink_smoke"));
    QStandardPaths::setTestModeEnabled(true);
    QApplication app(argc, argv);
    MainWebView view;
    // gui.exe:0x14001D103 jumps to the false-return path for activate.
    if (view.handleDeepLinks({QStringLiteral("program"), QStringLiteral("smartscanner://activate")})) return 1;
    if (view.handleDeepLinks({QStringLiteral("program")})) return 2;
    if (view.handleDeepLinks({QStringLiteral("program"), QStringLiteral("https://example.invalid")})) return 3;
    if (view.handleDeepLinks({QStringLiteral("program"), QStringLiteral("smartscanner://unknown")})) return 4;
    return 0;
}
