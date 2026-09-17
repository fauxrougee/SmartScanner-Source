// Native-derived offline factories/event fixtures. No HTTP requests are sent.
#include "manipulator.h"
#include "base64encoding.h"
#include "custominjectionvector.h"
#include "scanner.h"
#include <QCoreApplication>
#include <QNetworkCookie>
#include <cstdio>

struct ManipulatorTestAccess {
    static void detect(Manipulator &m, const ParameterInjectionPtr &p) { m.detectBase64(p); }
    static QString classify(Manipulator &m, const ParameterInjectionPtr &p) { return m.serializationType(p); }
};
namespace {
int failures = 0;
void check(bool ok, const char *label) {
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); }
}
QNetworkRequest::Attribute attr(int value) { return QNetworkRequest::Attribute(value); }
struct Capture { Event event; NetworkResponsePtr reply; ParameterInjectionPtr param; };
void capture(Manipulator &m, QList<Capture> &events) {
    QObject::connect(&m, &Manipulator::eventTriggered, &m,
        [&events](Event event, NetworkResponsePtr reply, ParameterInjectionPtr param) {
            events.append({event, reply, param});
        });
}
QSharedPointer<HttpResponse> response(const char *url) {
    auto r = QSharedPointer<HttpResponse>::create();
    r->url = QUrl(QString::fromLatin1(url));
    r->request = QNetworkRequest(r->url);
    return r;
}
ParameterInjectionPtr parameter(const QString &value) {
    return QSharedPointer<UrlParameterInjection>::create(
        QSharedPointer<CustomInjectionVector>::create(QStringLiteral("_Inject_Here_")),
        QStringLiteral("field"), value);
}
}
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    Base64Encoding encoding;
    check(encoding.transform("plain") == "cGxhaW4=" && encoding.decode("cGxhaW4=") == "plain", "native Base64 methods");
    {
        Manipulator m;
        auto p = parameter(QStringLiteral("===="));
        ManipulatorTestAccess::detect(m, p);
        check(p->value().isEmpty(), "permissive Base64 accepts empty decoded output");
        p = parameter(QStringLiteral("{"));
        check(ManipulatorTestAccess::classify(m, p).isNull(), "classifier length10 boundary");
        p = parameter(QStringLiteral("{not-json-but-long"));
        check(ManipulatorTestAccess::classify(m, p) == QStringLiteral("JSON"), "JSON is prefix heuristic, not parser validation");
        p = parameter(QStringLiteral("O:long-enough-value"));
        check(ManipulatorTestAccess::classify(m, p) == QStringLiteral("PHP"), "PHP prefix lowercased");
        p = parameter(QStringLiteral("rO0abcdefghijk"));
        check(ManipulatorTestAccess::classify(m, p) == QStringLiteral("JAVA"), "case-sensitive JAVA prefix");
        check(p->value() == QString::fromUtf8(QByteArray::fromBase64("rO0abcdefghijk")), "JAVA classification installs decoder");
    }
    {
        Manipulator m;
        QList<Capture> events;
        capture(m, events);
        auto r = response("https://example.invalid/a");
        auto p = parameter(QStringLiteral("{\"value\":1}"));
        m.manipulate(p, 64, r);
        check(events.size() == 2 && events[0].event.type == 8589934592ULL
              && events[0].event.data.toString() == QStringLiteral("JSON")
              && events[1].event.type == 64 && !events[1].event.data.isValid(), "serialization event precedes requested event");
        check(m.parameterCount == 1 && events[0].param == p && events[1].reply == r, "counter and shared event arguments");
    }
    {
        Manipulator m;
        m.vectorFlags = 1;
        QList<Capture> events;
        capture(m, events);
        auto r = response("https://example.invalid/a?=skip&a=old");
        m.scan(r);
        check(events.size() == 1 && events[0].event.type == 16, "query skips empty name");
        if (events.size() == 1) {
            const auto p = events[0].param;
            check(p->kind() == 1 && p->name() == QStringLiteral("a")
                  && p->value(QString(), 1) == QStringLiteral("old"), "query constructor name/value order");
            const auto mutated = p->apply(1, QStringLiteral("new"), QString(), QString(), r->request);
            check(mutated.url().query() == QStringLiteral("=skip&a=new"), "selected index includes skipped items");
        }
    }
    {
        Manipulator m;
        m.vectorFlags = 2;
        QList<Capture> events;
        capture(m, events);
        auto r = response("https://example.invalid/json");
        r->request.setAttribute(attr(1003), QByteArray("{\"a\":2,\"b\":\"hi\",\"c\":true}"));
        m.scan(r);
        check(events.size() == 3 && events[0].event.type == 256 && !events[0].param
              && events[1].event.type == 512 && events[2].event.type == 512, "JSON event then string/number factories only");
        if (events.size() == 3)
            check(events[1].param->name() == QStringLiteral("a") && events[2].param->name() == QStringLiteral("b"), "JSON Qt key order");
    }
    {
        Manipulator m;
        m.vectorFlags = 2;
        QList<Capture> events;
        capture(m, events);
        auto r = response("https://example.invalid/xml");
        r->request.setRawHeader("Content-Type", "APPLICATION/XML");
        r->request.setAttribute(attr(1003), QByteArray("{\"a\":2}"));
        m.scan(r);
        check(events.size() == 1 && events[0].event.type == 1024 && !events[0].param, "XML wins over JSON prefix");
        events.clear();
        r->request.setAttribute(attr(1003), QByteArray());
        m.scan(r);
        check(events.isEmpty(), "null payload stops");
        r->request.setAttribute(attr(1003), QByteArrayLiteral(""));
        m.scan(r);
        check(events.size() == 1 && events[0].event.type == 1024, "nonnull empty payload still classifies");
    }
    {
        Manipulator m;
        m.vectorFlags = 2;
        QList<Capture> events;
        capture(m, events);
        auto r = response("https://example.invalid/repair");
        r->request.setAttribute(attr(1003), QByteArray("{name:1}"));
        m.scan(r);
        check(events.size() == 2 && events[1].param->name() == QStringLiteral("name"), "native unquoted JSON-key repair");
    }
    {
        Manipulator m;
        m.vectorFlags = 16;
        QList<Capture> events;
        capture(m, events);
        auto r = response("https://example.invalid/item/12");
        r->request.setAttribute(attr(1011), 1);
        m.scan(r);
        check(events.isEmpty(), "path requires all505 bits, not any");
        r->request.setAttribute(attr(1011), 505);
        m.scan(r);
        check(events.size() == 1 && events[0].event.type == 32, "numeric path factory");
        if (events.size() == 1) {
            check(events[0].param->name() == QStringLiteral("https://example.invalid/item/_Inject_Here_")
                  && events[0].param->value(QString(), 1) == QStringLiteral("12"), "path stores pattern as name, number as value");
        }
        events.clear();
        m.scan(r);
        check(events.isEmpty(), "path signature suppresses repeat");
    }
    {
        Manipulator m;
        m.vectorFlags = 8;
        QList<Capture> events;
        capture(m, events);
        auto r = response("https://example.invalid/header");
        r->request.setRawHeader("User-Agent", "hi");
        r->field170 = true;
        m.scan(r);
        check(events.isEmpty(), "field170 gates headers before constraint");
        r->field170 = false;
        m.scan(r);
        check(events.size() == 2 && events[0].event.type == 4096 && events[1].event.type == 4096,
              "Referer/User-Agent event pair");
        if (events.size() == 2)
            check(events[0].param->name() == QStringLiteral("Referer")
                  && events[1].param->name() == QStringLiteral("User-Agent")
                  && events[1].param->value(QString(), 1) == QStringLiteral("hi"), "header values from separate native sources");
    }
    {
        NetworkManager manager{QString()}; // Null scan id avoids disk cache.
        QNetworkCookie cookie("session", "left%20right");
        cookie.setDomain(QStringLiteral("example.invalid"));
        cookie.setPath(QStringLiteral("/"));
        manager.setCookies({cookie});
        Manipulator m;
        m.networkManager = &manager;
        m.vectorFlags = 4;
        QList<Capture> events;
        capture(m, events);
        auto r = response("https://example.invalid/cookie");
        check(manager.cookiesForUrl(r->url).size() == 1 && manager.cookiesForUrl(r->url, 123).isEmpty(), "cookie lookup has no fallback");
        m.scan(r);
        check(events.isEmpty(), "cookie response must contain Set-Cookie name");
        r->raw = "sEt-CoOkIe";
        r->field120.append(HttpResponse::HeaderRange{
            HttpResponse::Range{0, 10}, HttpResponse::Range{10, 0}});
        m.scan(r);
        check(events.size() == 1 && events[0].event.type == 2048, "cookies fetched from manager, not response value");
        if (events.size() == 1)
            check(events[0].param->name() == QStringLiteral("session")
                  && events[0].param->value(QString(), 1) == QStringLiteral("left right"), "cookie value percent-decoded once");
        events.clear();
        m.scan(r);
        check(events.isEmpty(), "cookie signature suppresses repeats");
    }
    {
        Scanner scanner;
        check(scanner.manipulator().networkManager != nullptr, "Scanner binds manager to Manipulator");
    }
    return failures ? 1 : 0;
}
