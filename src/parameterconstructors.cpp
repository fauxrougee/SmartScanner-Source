#include "parameterinjection.h"

// Fixed-kind native constructors (kind constant is set by the base
// ParameterInjection constructor; the derived forwarders below supply it).
// Evidence: gui_parameter_constructors_wave10_hexrays.c, kinds written at the
// Parameter base (a1+80): Header==8 (l.33), Query==1 (l.118), Url==16 (l.192),
// Cookie==4 (l.266), Post==2 (l.315). Value/name are copied unchanged
// (l.31-32) and no validity check is performed during construction.

HeaderParameterInjection::HeaderParameterInjection(
    const QSharedPointer<InjectionVector> &vector, const QString &name, const QString &value)
    : ParameterInjection(8, vector, name, value) {}

QueryParameterInjection::QueryParameterInjection(
    const QSharedPointer<InjectionVector> &vector, const QString &name, const QString &value)
    : ParameterInjection(1, vector, name, value) {}

UrlParameterInjection::UrlParameterInjection(
    const QSharedPointer<InjectionVector> &vector, const QString &name, const QString &value)
    : ParameterInjection(16, vector, name, value) {}

PostParameterInjection::PostParameterInjection(
    const QSharedPointer<InjectionVector> &vector, const QString &name, const QString &value)
    : ParameterInjection(2, vector, name, value) {}

CookieParameterInjection::CookieParameterInjection(
    const QSharedPointer<InjectionVector> &vector, const QString &name, const QString &value)
    : ParameterInjection(4, vector, name, value) {}
