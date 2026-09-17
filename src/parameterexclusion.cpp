#include "parameterexclusion.h"

// Reconstructed from gui.exe 0x140110950. Lazy virtual calls per rule.
bool parameterExcluded(const QList<ParameterExclusionRule> &rules,
                       const Parameter &parameter, const QString &url) {
    for (const ParameterExclusionRule &rule : rules) {
        if (!rule.field08.match(parameter.name()).hasMatch())
            continue;

        const qint32 k = parameter.kind();
        if (k != 0 ? (rule.field18 & k) == k : rule.field18 == 0) {
            if (rule.field00.match(url).hasMatch()) {
                if (rule.field10.match(parameter.value(QString(), false)).hasMatch())
                    return true;
            }
        }
    }
    return false;
}
