// Offline fixtures for gui.exe ParameterInjection virtuals and BasicParameter.
// No HTTP requests are sent. Fake transforms/vectors below are test instruments.
#include "parameterinjection.h"
#include "keyvalueinjectionvector.h"
#include "urlencodedinjectionvector.h"
#include "custominjectionvector.h"
#include "cookieinjectionvector.h"
#include <QIODevice>
#include <QNetworkCookie>
#include <cstdio>

namespace {
int failures = 0;
void check(bool ok, const char *label) {
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); }
}
QNetworkRequest::Attribute attr(int number) { return QNetworkRequest::Attribute(number); }
class TraceTransform final : public NativeByteTransform {
public:
    TraceTransform(QByteArray *trace, char id) : trace(trace), id(id) {}
    QByteArray transform(const QByteArray &bytes) override {
        *trace += id; return bytes + id;
    }
    QByteArray decode(const QByteArray &bytes) override {
        *trace += id; return bytes + id;
    }
    QByteArray *trace;
    char id;
};
class TraceVector final : public InjectionVector {
public:
    bool valid = true;
    int called = 0;
    qint32 flags = 0;
    QString name;
    QVariant argument;
    QVariant result;
    qint32 supportedFlagsRaw() const override { return 0; }
    bool isValid() const override { return valid; }
    QVariant apply(qint32 f, const QByteArray &v, const QString &n) override {
        called = 1; flags = f; argument = v; name = n; return result;
    }
    QVariant apply(qint32 f, qint32 v, const QString &n) override {
        called = 2; flags = f; argument = v; name = n; return result;
    }
    QVariant apply(qint32 f, const QString &v, const QString &n) override {
        called = 3; flags = f; argument = v; name = n; return result;
    }
};
class TraceParameter final : public ParameterInjection {
public:
    using ParameterInjection::ParameterInjection;
    int calls = 0;
    QVariant seen;
protected:
    QNetworkRequest applyVariant(const QVariant &value, QNetworkRequest base) override {
        ++calls; seen = value; return base;
    }
};
QList<QByteArray> warningCategories;
void logMessage(QtMsgType type, const QMessageLogContext &context, const QString &) {
    if (type == QtWarningMsg) warningCategories.append(QByteArray(context.category));
}
}

int main()
{
    const QString empty;
    const QString inputName = QStringLiteral("renamed");
    const QString label = QStringLiteral("fixture");
    QNetworkRequest base(QUrl(QStringLiteral("https://example.invalid/old?a=b#fragment")));
    base.setRawHeader("X-Keep", "untouched");
    base.setHeader(QNetworkRequest::ContentLengthHeader, 123);
    base.setAttribute(attr(1008), QStringLiteral("old"));
    base.setAttribute(attr(1015), QVariant::fromValue(QList<QByteArray>{"existing"}));

    auto vector = QSharedPointer<TraceVector>::create();
    QByteArray trace;
    vector->field10.append(QSharedPointer<NativeByteTransform>(new TraceTransform(&trace, 'A')));
    vector->field10.append(QSharedPointer<NativeByteTransform>(new TraceTransform(&trace, 'B')));
    TraceParameter parameter(0, vector, QStringLiteral("original"), QStringLiteral("stored"));
    check(parameter.isValid(), "vector validity, not kind!=0");
    parameter.setValue(QStringLiteral("x"), 2);
    check(trace == "BA" && parameter.value(empty, 1) == QStringLiteral("xBA"), "mode2 encodes reverse");
    trace.clear();
    check(parameter.value(empty, 2) == QStringLiteral("xBAAB") && trace == "AB", "mode2 decodes forward");
    parameter.setValue(QStringLiteral(""), 1);
    trace.clear();
    check(parameter.value(QStringLiteral("fallback"), 0) == QStringLiteral("fallback") && trace.isEmpty(), "empty stored uses nonnull fallback");
    check(parameter.value(empty, 0) == QStringLiteral("AB") && trace == "AB", "null fallback still decodes empty stored");
    trace.clear();
    parameter.setValue(QStringLiteral("raw"), 1);
    check(trace.isEmpty(), "mode1 skips encoder");

    auto produced = parameter.apply(19, QByteArray("bytes"), inputName, label, base);
    const auto metadata = qvariant_cast<BasicParameter>(produced.attribute(attr(1014)));
    check(vector->called == 1 && vector->flags == 19 && vector->name == inputName
          && vector->argument.toByteArray() == "bytes", "byte overload forwarded");
    check(metadata.name == QStringLiteral("original") && metadata.value == QStringLiteral("raw")
          && metadata.kind == 0 && trace.isEmpty(), "metadata copies raw fields");
    check(produced.attribute(attr(1013)).toString() == label && !produced.attribute(attr(1008)).isValid(), "label and cleared attribute");
    check(parameter.calls == 1 && !parameter.seen.isValid(), "invalid vector result reaches final virtual");
    parameter.apply(2, qint32(-7), inputName, label, base);
    check(vector->called == 2 && vector->argument.toInt() == -7, "signed integer overload");
    parameter.apply(8, QStringLiteral("string"), inputName, label, base);
    check(vector->called == 3 && vector->argument.metaType().id() == QMetaType::QString, "string overload");
    vector->valid = false;
    const int priorCalls = parameter.calls;
    check(parameter.apply(1, QByteArray("x"), empty, label, base) == QNetworkRequest()
          && parameter.calls == priorCalls, "invalid parameter returns default request");
    parameter.setValue(QStringLiteral("ignored"), 1);
    check(parameter.value(label, 1) == label, "invalid getter returns fallback");
    vector->valid = true;
    check(parameter.value(empty, 1) == QStringLiteral("raw"), "invalid setter preserved storage");

    auto key = QSharedPointer<KeyValueInjectionVector>::create(QByteArray("X-Test"), QByteArray("old"));
    HeaderParameterInjection header(8, key, QStringLiteral("X-Test"), QStringLiteral("old"));
    produced = header.apply(1, QByteArray("new"), empty, label, base);
    check(produced.rawHeader("X-Test") == "new" && produced.rawHeader("X-Keep") == "untouched", "header set, unrelated preserved");
    produced = header.apply(1, QByteArray("again"), empty, label, produced);
    check(produced.attribute(attr(1015)).value<QList<QByteArray>>()
          == QList<QByteArray>({"existing", "X-Test", "X-Test"}), "header tracking preserves duplicates");

    auto queryVector = QSharedPointer<UrlEncodedInjectionVector>::create(
        UrlEncodedInjectionVector::QueryItems{{QStringLiteral("a"), QStringLiteral("b")}}, 0);
    QueryParameterInjection query(1, queryVector, QStringLiteral("a"), QStringLiteral("b"));
    produced = query.apply(1, QStringLiteral("c"), empty, label, base);
    check(produced.url().toString() == QStringLiteral("https://example.invalid/old?a=c#fragment"), "query preserves path/fragment");

    auto custom = QSharedPointer<CustomInjectionVector>::create(QStringLiteral("_Inject_Here_"));
    UrlParameterInjection url(16, custom, empty, empty);
    produced = url.apply(17, QByteArray("/relative?q=v"), empty, label, base);
    check(produced.url().isRelative() && produced.url().toString() == QStringLiteral("/relative?q=v"), "URL replacement does not resolve relative");

    PostParameterInjection post(2, queryVector, QStringLiteral("a"), QStringLiteral("b"));
    produced = post.apply(1, QStringLiteral("c"), empty, label, base);
    check(produced.attribute(attr(1003)).metaType().id() == QMetaType::QByteArray
          && produced.attribute(attr(1003)).toByteArray() == "a=c"
          && !produced.header(QNetworkRequest::ContentLengthHeader).isValid(), "POST body and cleared length");
    check(produced.url() == base.url() && produced.rawHeader("X-Keep") == "untouched", "POST preserves unrelated fields");

    const QList<QNetworkCookie> cookies{QNetworkCookie("session", "old")};
    auto cookieVector = QSharedPointer<CookieInjectionVector>::create(cookies, 0);
    CookieParameterInjection cookie(4, cookieVector, QStringLiteral("session"), QStringLiteral("old"));
    produced = cookie.apply(17, QByteArray("new"), empty, label, base);
    check(produced.header(QNetworkRequest::CookieHeader).value<QList<QNetworkCookie>>()
          == QList<QNetworkCookie>({QNetworkCookie("session", "new")}), "cookie typed header");
    check(produced.attribute(attr(1015)).value<QList<QByteArray>>() == QList<QByteArray>({"existing", "Cookie"}), "cookie tracking capital C");
    check(base.rawHeader("X-Test").isEmpty() && base.attribute(attr(1008)).toString() == QStringLiteral("old")
          && base.header(QNetworkRequest::ContentLengthHeader).toInt() == 123, "all producers copy original request");

    // Valid fake vector returning a deliberately nonconvertible QVariant.
    vector->result = QVariant::fromValue(BasicParameter{});
    const auto previousHandler = qInstallMessageHandler(logMessage);
    HeaderParameterInjection badHeader(8, vector, empty, empty);
    QueryParameterInjection badQuery(1, vector, empty, empty);
    UrlParameterInjection badUrl(16, vector, empty, empty);
    PostParameterInjection badPost(2, vector, empty, empty);
    CookieParameterInjection badCookie(4, vector, empty, empty);
    produced = badHeader.apply(1, qint32(0), empty, label, base);
    check(produced.attribute(attr(1015)).value<QList<QByteArray>>().size() == 2, "failed pair conversion still appends");
    produced = badQuery.apply(1, qint32(0), empty, label, base);
    check(!produced.url().hasQuery() && produced.url().path() == QStringLiteral("/old"), "failed query conversion still mutates");
    produced = badUrl.apply(1, qint32(0), empty, label, base);
    check(produced.url().isEmpty(), "failed URL conversion still replaces");
    produced = badPost.apply(1, qint32(0), empty, label, base);
    check(!produced.header(QNetworkRequest::ContentLengthHeader).isValid()
          && produced.attribute(attr(1003)).metaType().id() == QMetaType::QByteArray, "failed POST conversion still clears length and sets typed body");
    produced = badCookie.apply(1, qint32(0), empty, label, base);
    check(produced.attribute(attr(1015)).value<QList<QByteArray>>().last() == "Cookie", "failed cookie conversion still tracks header");
    qInstallMessageHandler(previousHandler);
    for (const auto &kind : QList<QByteArray>{"Header", "Query", "Url", "Post", "Cookie"})
        check(warningCategories.contains("ParameterInjection." + kind + "ParameterInjection"), "native warning category");

    QByteArray bytes;
    QDataStream writer(&bytes, QIODevice::WriteOnly);
    writer << BasicParameter{QString(), QStringLiteral("A"), -2};
    check(bytes == QByteArray::fromHex("ffffffff000000020041fffffffe"), "BasicParameter stream field order and signedness");
    QDataStream reader(bytes);
    BasicParameter restored;
    reader >> restored;
    check(restored.name.isNull() && restored.value == QStringLiteral("A") && restored.kind == -2, "BasicParameter input stream");
    return failures ? 1 : 0;
}
