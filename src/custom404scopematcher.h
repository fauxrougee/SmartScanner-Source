#pragma once

#include <QString>
#include <QStringList>

// gui.exe:0x14014D440, with the QUrl::fromUserInput wrapper at 0x140123470.
// Returns whether `candidate` belongs to at least one already-stored scope.
[[nodiscard]] bool custom404MatchesStoredScope(const QString &candidate,
                                                const QStringList &storedScopes);
