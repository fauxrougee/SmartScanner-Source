#include "fileliststream.h"

QDataStream &operator<<(QDataStream &stream, const FileListFilterState &state)
{
    // gui.exe:0x1400E23F0 and 0x1400DED70
    stream << state.field08 << state.field0C << state.field10 << state.field18 << state.field20;
    return stream;
}

QDataStream &operator>>(QDataStream &stream, FileListFilterState &state)
{
    // gui.exe:0x1400E17C0 and 0x1400DD990
    stream >> state.field08 >> state.field0C >> state.field10 >> state.field18 >> state.field20;
    return stream;
}

QDataStream &operator<<(QDataStream &stream, const FileListStreamState &state)
{
    // FileList slice of gui.exe:0x1400E2910
    stream << state.field18 << state.field34 << state.field50 << state.field58 << state.field70
           << state.field90 << state.fieldB0 << state.fieldD8 << state.field118 << state.field11C
           << state.field120 << state.field124 << state.field128 << state.field12C << state.field130
           << state.field134;
    writeRequestItems(stream, state.field78);
    return stream;
}

QDataStream &operator>>(QDataStream &stream, FileListStreamState &state)
{
    // FileList slice of gui.exe:0x1400E1CA0
    stream >> state.field18 >> state.field34 >> state.field50 >> state.field58 >> state.field70
           >> state.field90 >> state.fieldB0 >> state.fieldD8 >> state.field118 >> state.field11C
           >> state.field120 >> state.field124 >> state.field128 >> state.field12C >> state.field130
           >> state.field134;
    readRequestItems(stream, state.field78);
    return stream;
}
