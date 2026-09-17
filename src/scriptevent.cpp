#include "scriptevent.h"
#include <QStringView>
#include <QHashFunctions>

// gui.exe:0x1401073D0. A nonzero cached identity is never invalidated here.
quint64 Event::identityHash()
{
    if (!field28) {
        const QString text = QStringLiteral("evt:%1:%2").arg(type).arg(data.toString());
        field28 = qHash(QStringView(text), size_t(0));
    }
    return field28;
}
