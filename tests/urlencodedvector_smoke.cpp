// Offline fixtures for gui.exe:0x1400AAB80, 0x1400AA620..0x1400AA710,
// and encoder traversal 0x140086EF0. Expected strings do not call QUrlQuery.
#include "urlencodedinjectionvector.h"
#include <cstdio>
#include <utility>

namespace {
int failures = 0;
void check(bool ok, const char *label)
{
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL: %s\n", label);
    }
}
void expect(const QVariant &value, const QString &text, const char *label)
{
    check(value.metaType().id() == QMetaType::QString && value.toString() == text, label);
}
// Test-only transforms: append tags and record order, not native algorithms.
class AppendTag final : public NativeByteTransform {
public:
    AppendTag(QList<int> *calls, int tag) : calls(calls), tag(tag) {}
    QByteArray transform(const QByteArray &input) override {
        calls->append(tag);
        return input + QByteArray::number(tag);
    }
    QList<int> *calls;
    QByteArray decode(const QByteArray &) override
    {
        qFatal("Unexpected decode in encode-only fixture");
        return {};
    }
    int tag;
};
}

int main()
{
    using Vector = UrlEncodedInjectionVector;
    const Vector::QueryItems single{{QStringLiteral("a"), QStringLiteral("old")}};
    const QString ignored = QStringLiteral("ignored");
    Vector empty({}, 0), negative(single, -1), beyond(single, 1), v(single, 0);
    check(!empty.isValid() && !negative.isValid() && !beyond.isValid() && v.isValid(), "index bounds");
    check(!empty.apply(1, ignored, ignored).isValid()
          && !negative.apply(1, ignored, ignored).isValid()
          && !beyond.apply(1, ignored, ignored).isValid(), "invalid index -> invalid QVariant");
    check(v.supportedFlagsRaw() == 63, "supported mask");
    check(!v.apply(0, ignored, ignored).isValid(), "no action");
    check(!v.apply(16 | 32, ignored, ignored).isValid(), "modifiers alone are not actions");
    expect(v.apply(1, QStringLiteral("x+y"), ignored), QStringLiteral("a=x%2By"), "plus escaping");
    expect(v.apply(1 | 16, QStringLiteral("x+y"), ignored), QStringLiteral("a=x%2By"), "raw modifier still escapes plus");
    expect(v.apply(1 | 32, QStringLiteral("x+y"), ignored), QStringLiteral("a=x+y"), "placeholder bypass");
    expect(v.apply(1, QStringLiteral("a&b"), ignored), QStringLiteral("a=a%26b"), "query delimiter escaping");
    expect(v.apply(1 | 16 | 32, QStringLiteral("a&b"), ignored), QStringLiteral("a=a&b"), "raw placeholder replacement");
    expect(v.apply(2, ignored, ignored), QStringLiteral("a"), "null value removes equals");
    expect(v.apply(1 | 2, QStringLiteral("alpha"), ignored), QStringLiteral("a"), "clear overrides transformed value");
    expect(v.apply(4 | 8, ignored, QStringLiteral("b+c")), QStringLiteral("b%2Bc=old"), "rename wins over removal");
    expect(v.apply(8, ignored, ignored), QStringLiteral(""), "remove only returns valid empty string");
    expect(v.apply(4, ignored, QStringLiteral("b")), QStringLiteral("b=old"), "previous operations did not mutate source");
    expect(v.apply(1, qint32(-12), ignored), QStringLiteral("a=-12"), "signed integer overload");
    const QByteArray utf8 = QByteArray::fromHex("c3a9");
    expect(v.apply(1 | 32, utf8, ignored), QStringLiteral("a=") + QString::fromUtf8(utf8), "UTF8 byte overload");

    const Vector::QueryItems duplicates{{QStringLiteral("a"), QStringLiteral("first")},
                                        {QStringLiteral("a"), QStringLiteral("second")}};
    Vector second(duplicates, 1);
    expect(second.apply(1, QStringLiteral("alpha"), ignored), QStringLiteral("a=first&a=alpha"), "index selects duplicate");
    expect(second.apply(8, ignored, ignored), QStringLiteral("a=first"), "remove selected duplicate");
    expect(second.apply(1, QStringLiteral("alpha"), ignored), QStringLiteral("a=first&a=alpha"), "repeat after deletion");
    Vector marker({{QStringLiteral("_Decoded_Place_"), QStringLiteral("_Decoded_Place_")}}, 0);
    expect(marker.apply(1, QStringLiteral("alpha"), ignored), QStringLiteral("alpha=alpha"), "replace marker globally even without bit32");

    QList<int> calls;
    v.field10.append(QSharedPointer<NativeByteTransform>(new AppendTag(&calls, 1)));
    v.field10.append(QSharedPointer<NativeByteTransform>(new AppendTag(&calls, 2)));
    expect(v.apply(1, QStringLiteral("alpha"), ignored), QStringLiteral("a=alpha21"), "reverse transform data flow");
    check(calls == QList<int>{2, 1}, "reverse transform order");
    calls.clear();
    expect(v.apply(1 | 16, QStringLiteral("alpha"), ignored), QStringLiteral("a=alpha"), "raw override discards chain result");
    check(calls == QList<int>{2, 1}, "raw override still runs chain");
    return failures ? 1 : 0;
}
