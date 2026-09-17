#pragma once

class HttpResponse;

// gui.exe:0x14014CE80. Detects response evidence that the shared Custom404
// classifier treats as a known error page.
[[nodiscard]] bool custom404HasErrorEvidence(const HttpResponse &response);
