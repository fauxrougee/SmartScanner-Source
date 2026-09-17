#pragma once

#include <QString>

struct Issue;

// Reconstruction label for gui.exe:0x140046D70 / 0x140046ED0.  Those paths
// load assets/issues/generic-min.json and overlay an Issue with its compact
// catalogue representation before an individual compiled test sets its URL,
// identity and impact.
class IssueTemplate final
{
public:
    static bool applyGeneric(Issue *issue, const QString &name,
                             const QString &path);
};
