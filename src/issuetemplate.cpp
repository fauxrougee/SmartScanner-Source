#include "issuetemplate.h"

#include "issue.h"
#include "issuedbdata.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>

namespace {

QList<QString> strings(const QJsonArray &values)
{
    QList<QString> result;
    result.reserve(values.size());
    for (const QJsonValue &value : values)
        result.append(value.toString());
    return result;
}

void applyClassification(Issue *issue, const QJsonObject &classification)
{
    // gui.exe:0x140046ED0 compact `cl` map, in native Issue offset order.
    issue->field118 = strings(classification.value(QStringLiteral("w")).toArray());
    issue->field130 = strings(classification.value(QStringLiteral("c3")).toArray());
    issue->field148 = strings(classification.value(QStringLiteral("c4")).toArray());
    issue->field160 = strings(classification.value(QStringLiteral("cv")).toArray());
    issue->field178 = strings(classification.value(QStringLiteral("e")).toArray());
    issue->field190 = strings(classification.value(QStringLiteral("g")).toArray());
    issue->field1A8 = strings(classification.value(QStringLiteral("cw")).toArray());
    issue->field1C0 = strings(classification.value(QStringLiteral("o")).toArray());
    issue->field1D8 = strings(classification.value(QStringLiteral("ca")).toArray());
    issue->field1F0 = strings(classification.value(QStringLiteral("iso")).toArray());
    issue->field208 = strings(classification.value(QStringLiteral("h")).toArray());
    issue->field220 = strings(classification.value(QStringLiteral("p")).toArray());
}

} // namespace

bool IssueTemplate::applyGeneric(Issue *issue, const QString &name,
                                 const QString &path)
{
    if (!issue)
        return false;

    QJsonObject catalogue;
    if (!IssueDbData::loadJson(path, &catalogue))
        return false;

    const QJsonObject value = catalogue.value(name).toObject();
    if (value.isEmpty())
        return false;

    // `name` is passed as the non-null third parameter at 0x140046E8C, so it
    // overrides compact key `n`.  Key `di` remains native Issue +0x00.
    issue->field00 = value.value(QStringLiteral("di")).toString();
    issue->field18 = name;
    issue->fieldA8 = value.value(QStringLiteral("d")).toString();
    issue->fieldC0 = value.value(QStringLiteral("r")).toString();
    issue->field38 = value.value(QStringLiteral("i")).toInt();

    issue->fieldD8.clear();
    for (const QJsonValue &reference : value.value(QStringLiteral("rf")).toArray()) {
        const QJsonObject object = reference.toObject();
        issue->fieldD8.append({object.value(QStringLiteral("tt")).toString(),
                               object.value(QStringLiteral("url")).toString()});
    }
    applyClassification(issue, value.value(QStringLiteral("cl")).toObject());
    return true;
}
