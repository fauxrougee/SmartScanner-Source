#pragma once
#include "parameter.h"
#include "scanconfig.h"
// gui.exe:0x140110950. The Parameter getters are virtual and evaluated lazily.
bool parameterExcluded(const QList<ParameterExclusionRule> &rules,
                       const Parameter &parameter, const QString &url);
