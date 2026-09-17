#include "issuedbstream.h"

QDataStream &operator<<(QDataStream &stream, const IssueDbStreamState &state)
{
    // Exact component order from gui.exe:0x1400E2590.
    stream << state.field2A0;
    stream << state.field2B8;
    stream << state.field2C0;
    stream << state.field2C8;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, IssueDbStreamState &state)
{
    // Direct inverse of gui.exe:0x1400E1930.
    stream >> state.field2A0;
    stream >> state.field2B8;
    stream >> state.field2C0;
    stream >> state.field2C8;
    return stream;
}
