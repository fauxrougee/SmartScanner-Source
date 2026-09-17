#pragma once

class HttpResponse;

// gui.exe:0x14014C770 as called by 0x14014DEF0 with its native empty QString
// auxiliary argument. True means the shared classifier bypasses error evidence.
[[nodiscard]] bool custom404ResponseBypassesErrorEvidence(const HttpResponse &response);
