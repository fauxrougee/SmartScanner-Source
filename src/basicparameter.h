#pragma once
#include <QString>
#include <QMetaType>
#include <QDataStream>

// Native metatype name at gui.exe:0x1402c8678, fields observed at0/24/48.
struct BasicParameter {
    QString name;
    QString value;
    qint32 kind = 0;
};
QDataStream &operator<<(QDataStream &, const BasicParameter &);
QDataStream &operator>>(QDataStream &, BasicParameter &);
Q_DECLARE_METATYPE(BasicParameter)
