// Offline smoke test for the five fixed-kind native constructors.
// Exercised only the kind/name/value state proven in
// decompiled/gui_parameter_constructors_wave10_hexrays.c.
#include "parameterinjection.h"
#include "keyvalueinjectionvector.h"
#include <QByteArray>
#include <QCoreApplication>
#include <QSharedPointer>
#include <QString>
#include <cstdio>

static int g_failures = 0;

static void check(bool condition, const char *message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++g_failures;
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // A valid shared vector, kept alive as a shared pointer.
    auto vector = QSharedPointer<KeyValueInjectionVector>::create(
        QByteArrayLiteral("k"), QByteArrayLiteral("v"));

    const QString name = QStringLiteral("name");
    const QString value = QStringLiteral("value");

    HeaderParameterInjection header(vector, name, value);
    QueryParameterInjection query(vector, name, value);
    UrlParameterInjection url(vector, name, value);
    PostParameterInjection post(vector, name, value);
    CookieParameterInjection cookie(vector, name, value);

    Parameter *all[] = { &header, &query, &url, &post, &cookie };
    const qint32 expected[] = { 8, 1, 16, 2, 4 };

    for (int i = 0; i < 5; ++i) {
        check(all[i]->kind() == expected[i], "fixed kind mismatch");
        check(all[i]->name() == name, "name not retained");
        check(all[i]->value(QString(), 1) == value, "value not retained unchanged");
        check(all[i]->isValid(), "valid vector should keep kind nonzero valid");
    }

    // Null vector: invalid even though the kind is nonzero.
    QSharedPointer<InjectionVector> nullVector;
    QueryParameterInjection nullQuery(nullVector, name, value);
    check(nullQuery.kind() == 1, "null-vector kind still stored");
    check(!nullQuery.isValid(), "null vector must be invalid even for kind 1");

    // A separate vector has only the parameter's retained strong reference.
    QSharedPointer<InjectionVector> retained = QSharedPointer<KeyValueInjectionVector>::create(
        QByteArrayLiteral("key"), QByteArrayLiteral("stored"));
    QWeakPointer<InjectionVector> weak(retained);
    {
        QueryParameterInjection owner(retained, QString(), QStringLiteral(""));
        retained.clear();
        check(!weak.isNull() && owner.isValid(), "parameter retains shared vector");
        check(owner.name().isNull() && !owner.value(QString(), 1).isNull(),
              "constructor preserves null name and empty nonnull stored value");
    }
    check(weak.isNull(), "vector released with last parameter");

    if (g_failures == 0)
        std::fprintf(stdout, "parameterconstructor_smoke: OK\n");
    return g_failures == 0 ? 0 : 1;
}
