#pragma once

#include <QJsonObject>
#include <QString>

// Reconstructed from gui.exe:0x1400493D0. The binary keeps one
// mutex-protected, lazy-loaded QJsonObject shared by all callers.
class IssueDbData final {
public:
    static bool loadJson(const QString &path, QJsonObject *result,
                         QString *error = nullptr);
};
