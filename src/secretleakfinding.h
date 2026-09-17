#pragma once

#include "secretleakmatcher.h"

class HttpResponse;
class IssueDb;

// Reconstruction label for gui.exe:0x140045630, virtual slot 11 of the
// RTTI-named SecretLeak vtable at 0x1402C82E8.  Native inputs:
//   a1+112 retained response (TestScript response slot),
//   a1+40  IssueDb receiver of 0x1401257B0,
//   qword_140360C88 static matcher configuration.
// This is a source-level free function, not the native class/ABI: the
// SecretLeak object, its factory registration and the loader producing the
// configuration are not reconstructed.
// Returns true when an Issue was submitted to IssueDb (source-only result;
// the native slot returns void).
bool secretLeakProcessResponse(const HttpResponse *response, IssueDb *issueDb,
                               const SecretLeakConfig &config,
                               const QString &genericIssueDataPath);
