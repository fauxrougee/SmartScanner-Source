#pragma once

#include "filecountconstrain.h"

// gui.exe RTTI names this FileCountConstrain derivative DirCountConstrain.
class DirCountConstrain final : public FileCountConstrain {
public:
    DirCountConstrain();

    // gui.exe:0x140160BE0, virtual slot 0.
    bool acceptAndRecord(const QUrl &url) override;

    QSet<quint64> field28;
    qint32 field30 = 0;
};
