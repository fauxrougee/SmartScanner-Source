#pragma once

#include <QByteArray>
#include <QDataStream>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QPair>
#include <QRecursiveMutex>
#include <QSet>
#include <QString>
#include <QUrl>

// Recovered from gui.exe:0x1400217F0, 0x140022D00, 0x140023140, and
// 0x1400DD100.  Member names intentionally preserve binary offsets: the
// original identifiers have not been recovered.
struct Issue
{
    Issue() = default;
    Issue(const Issue &other);
    Issue(Issue &&other);
    Issue &operator=(const Issue &other);
    Issue &operator=(Issue &&other);

    [[nodiscard]] quint64 identity();
    [[nodiscard]] QJsonObject toJsonObject() const;

    QString field00;
    QString field18;
    QUrl field30;
    qint32 field38 = 0;
    QString field40;
    QString field58;
    QString field70;
    QString field88;
    qint32 fieldA0 = 0;
    QString fieldA8;
    QString fieldC0;
    QList<QPair<QString, QString>> fieldD8;
    QList<QPair<QByteArray, QByteArray>> fieldF0;
    QHash<QString, QSet<QString>> field108;
    qint32 field110 = 0;
    QList<QString> field118;
    QList<QString> field130;
    QList<QString> field148;
    QList<QString> field160;
    QList<QString> field178;
    QList<QString> field190;
    QList<QString> field1A8;
    QList<QString> field1C0;
    QList<QString> field1D8;
    QList<QString> field1F0;
    QList<QString> field208;
    QList<QString> field220;
    QRecursiveMutex field238;
    quint64 field250 = 0;
    bool field258 = false;
    QList<QString> field260;
};

QDataStream &operator<<(QDataStream &stream, const Issue &issue);
QDataStream &operator>>(QDataStream &stream, Issue &issue);
