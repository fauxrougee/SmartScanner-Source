#pragma once
#include <QList>
#include <QMetaType>
#include <QString>

// Native Qt metatype ScriptURI; layout +0/+8/+32/+56 established by
// gui.exe:0x14010B800 and 0x1401067C0. Public field names reconstructed.
struct ScriptURI {
    qint32 priority = -1;
    QList<quint64> triggers;
    QString options;
    QString name;
    ScriptURI() = default;
    explicit ScriptURI(const QString &text) { parse(text); }
    void parse(const QString &text);
    QString toString() const;
    static QList<quint64> splitTriggerMask(quint64 mask);
    static void decodeOptions(QString &text);
};
Q_DECLARE_METATYPE(ScriptURI)
