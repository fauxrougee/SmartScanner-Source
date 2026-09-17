#include "basicparameter.h"

// gui.exe:0x1400444F0 / 0x140044490. QString, QString, signed32 in order.
QDataStream &operator<<(QDataStream &stream, const BasicParameter &parameter)
{
    return stream << parameter.name << parameter.value << parameter.kind;
}
QDataStream &operator>>(QDataStream &stream, BasicParameter &parameter)
{
    return stream >> parameter.name >> parameter.value >> parameter.kind;
}
