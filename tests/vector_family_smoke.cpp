// Native GUI vector/Parameter fixtures. No HTTP, process launch or scan.
#include "keyvalueinjectionvector.h"
#include "custominjectionvector.h"
#include "cookieinjectionvector.h"
#include "jsonobjectyinjectionvector.h"
#include "parameterexclusion.h"
#include <QJsonDocument>
#include <cstdio>

namespace {
int failures = 0;
void check(bool result, const char *label) {
    if (!result) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); }
}
class Tag final : public NativeByteTransform {
public:
    int calls = 0;
    QByteArray transform(const QByteArray &bytes) override { ++calls; return bytes + "!"; }
    QByteArray decode(const QByteArray &) override
    {
        qFatal("Unexpected decode in encode-only fixture");
        return {};
    }
};
class ObservedParameter final : public Parameter {
public:
    using Parameter::Parameter;
    mutable QString trace;
    QString name() const override { trace += QLatin1Char('n'); return Parameter::name(); }
    qint32 kind() const override { trace += QLatin1Char('k'); return Parameter::kind(); }
    QString value(const QString &fallback, qint32 raw) const override {
        trace += QLatin1Char('v'); return Parameter::value(fallback, raw);
    }
};
}

int main()
{
    const QString ignored;
    KeyValueInjectionVector key(QByteArrayLiteral("key"), QByteArrayLiteral("old"));
    KeyValueInjectionVector nullKey(QByteArray(), QByteArrayLiteral("old"));
    KeyValueInjectionVector emptyKey(QByteArrayLiteral(""), QByteArrayLiteral("old"));
    auto tag = QSharedPointer<Tag>::create();
    key.field10.append(tag);
    check(key.supportedFlagsRaw() == 1 && !nullKey.isValid() && emptyKey.isValid(), "key validity/mask");
    const QVariant pairFailure = key.apply(0, QByteArrayLiteral("new"), ignored);
    check(pairFailure.metaType() == QMetaType::fromType<NativeBytePair>()
        && pairFailure.value<NativeBytePair>().first.isNull()
        && pairFailure.value<NativeBytePair>().second.isNull(), "typed null pair");
    const NativeBytePair pair = key.apply(1, qint32(-3), ignored).value<NativeBytePair>();
    check(pair.first == "key" && pair.second == "-3" && tag->calls == 0, "key has no transform chain");

    CustomInjectionVector custom(QStringLiteral("before/_Inject_Here_/_Inject_Here_"));
    custom.field10.append(tag);
    const QVariant customFailure = custom.apply(0, QByteArrayLiteral("x"), ignored);
    check(customFailure.metaType().id() == QMetaType::QString && customFailure.toString().isNull(), "typed null custom string");
    check(custom.apply(1, QByteArrayLiteral("a b"), ignored).toString()
          == QStringLiteral("before/a%20b%21/a%20b%21"), "custom transform then percent encode");
    check(custom.apply(17, QByteArrayLiteral("a b"), ignored).toString()
          == QStringLiteral("before/a b/a b") && tag->calls == 1, "custom raw bypasses chain");

    QNetworkCookie cookie(QByteArrayLiteral("name"), QByteArrayLiteral("old"));
    cookie.setDomain(QStringLiteral("example.invalid"));
    cookie.setPath(QStringLiteral("/test"));
    CookieInjectionVector cookies({cookie}, 0);
    cookies.field10.append(tag);
    const QVariant cookieFailure = cookies.apply(0, QByteArrayLiteral("x"), ignored);
    check(cookieFailure.metaType() == QMetaType::fromType<QList<QNetworkCookie>>()
          && cookieFailure.value<QList<QNetworkCookie>>().isEmpty(), "typed empty cookie list");
    const auto changed = cookies.apply(1, QByteArrayLiteral("new"), ignored).value<QList<QNetworkCookie>>();
    check(changed.size() == 1 && changed.first().value() == "new!"
          && changed.first().name() == cookie.name()
          && changed.first().domain() == cookie.domain()
          && changed.first().path() == cookie.path() && cookie.value() == "old", "cookie copy/value/metadata");
    check(cookies.apply(17, QByteArrayLiteral("raw"), ignored).value<QList<QNetworkCookie>>().first().value() == "raw"
          && tag->calls == 2, "cookie raw bypasses chain");

    const QJsonObject original{{QStringLiteral("a"), QStringLiteral("old")}};
    JsonObjectyInjectionVector json(original, QStringLiteral("a"));
    json.field10.append(tag);
    check(json.supportedFlagsRaw() == 27 && json.isValid(), "json mask/validity");
    check(!json.apply(0, QStringLiteral("x"), ignored).isValid(), "json invalid no-action");
    const QVariant integer = json.apply(1 | 2 | 16, qint32(-7), ignored);
    check(integer.metaType().id() == QMetaType::QByteArray
          && integer.toByteArray() == "{\n    \"a\": -7\n}\n" && tag->calls == 2, "json integer precedence and indented format");
    check(json.apply(2, QStringLiteral("x"), ignored).toByteArray() == "{\n    \"a\": null\n}\n", "json null not number zero");
    check(QJsonDocument::fromJson(json.apply(1 | 8, QStringLiteral("x"), ignored).toByteArray()).object().isEmpty()
          && tag->calls == 3, "json removal follows transformed edit");
    check(json.apply(17, QStringLiteral("raw"), ignored).toByteArray() == "{\n    \"a\": \"raw\"\n}\n"
          && tag->calls == 3 && original.value(QStringLiteral("a")).toString() == QStringLiteral("old"), "json raw and source isolation");

    Parameter p(31, QStringLiteral("name"), QStringLiteral(""));
    check(p.isValid() && p.kindName().isEmpty() && !p.kindName().isNull(), "kind31 empty non-null label");
    check(p.value(QStringLiteral("fallback")) == QStringLiteral("fallback")
          && !p.value().isNull(), "parameter empty stored value fallback");
    p.setKind(0);
    check(!p.isValid() && p.kindName().isNull(), "unknown kind null label");
    p.setName(QStringLiteral("renamed")); p.setValue(QStringLiteral("value"));
    check(p.name() == QStringLiteral("renamed") && p.value(QStringLiteral("fallback")) == QStringLiteral("value"), "parameter setters");

    ObservedParameter observed(2, QStringLiteral("name"), QStringLiteral("value"));
    ParameterExclusionRule rule;
    rule.field00 = QRegularExpression(QStringLiteral("^url$"));
    rule.field08 = QRegularExpression(QStringLiteral("^different$"));
    rule.field10 = QRegularExpression(QStringLiteral("^value$"));
    rule.field18 = 31;
    check(!parameterExcluded({rule}, observed, QStringLiteral("url")) && observed.trace == QStringLiteral("n"), "exclusion name short circuit");
    rule.field08 = QRegularExpression(QStringLiteral("^name$"));
    observed.trace.clear();
    check(parameterExcluded({rule}, observed, QStringLiteral("url")) && observed.trace == QStringLiteral("nkv"), "exclusion virtual call order");
    observed.setKind(0); observed.trace.clear();
    check(!parameterExcluded({rule}, observed, QStringLiteral("url")) && observed.trace == QStringLiteral("nk"), "zero kind does not match any mask");
    rule.field18 = 0;
    check(parameterExcluded({rule}, observed, QStringLiteral("url")), "zero kind matches zero mask");
    return failures ? 1 : 0;
}
