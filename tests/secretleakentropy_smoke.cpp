#include "secretleakentropy.h"

#include <QCoreApplication>
#include <QtGlobal>

#include <cmath>
#include <cstdlib>
#include <iostream>

namespace {

void require(bool value, const char *message)
{
    if (!value) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

bool closeTo(double actual, double expected)
{
    return std::abs(actual - expected) < 1e-12;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    require(closeTo(secretLeakTextEntropy(QString()), 0.0),
            "null QString has zero native entropy");
    require(closeTo(secretLeakTextEntropy(QStringLiteral("")), 0.0),
            "empty QString has zero native entropy");
    require(closeTo(secretLeakTextEntropy(QStringLiteral("aaaa")), 0.0),
            "one distinct QChar has zero entropy");
    require(closeTo(secretLeakTextEntropy(QStringLiteral("aabb")), 1.0),
            "two equally frequent QChars have entropy one");
    require(closeTo(secretLeakTextEntropy(QStringLiteral("abc")), std::log2(3.0)),
            "three equally frequent QChars have entropy log2(3)");
    // The native increments a counter while walking QString::begin/end by two
    // bytes, so a supplementary-plane scalar is counted as its two UTF-16 units.
    require(closeTo(secretLeakTextEntropy(QString::fromUtf8("\xF0\x9F\x98\x80")), 1.0),
            "supplementary scalar is counted as two distinct UTF-16 QChars");

    const QString lines = QStringLiteral("zero\nalpha\nomega");
    require(secretLeakContextLine(lines, -1).isNull(),
            "negative offset returns the native default QString");
    // gui.exe:0x140045A40 tests the signed parameter with `a4 < 0`, so any
    // negative offset (not just -1) takes the default-constructed QString path.
    require(secretLeakContextLine(lines, -42).isNull(),
            "any negative offset returns the native default QString (a4 < 0)");
    require(secretLeakContextLine(lines, lines.size()).isNull(),
            "offset at QString size returns the native default QString");
    require(secretLeakContextLine(lines, 1) == QStringLiteral("zero"),
            "offset within a line returns that line");
    require(secretLeakContextLine(lines, 6) == QStringLiteral("alpha"),
            "offset after newline returns following line");
    require(secretLeakContextLine(lines, 4) == QStringLiteral("alpha\nomega"),
            "offset on newline preserves native negative mid length behavior");

    const QRegularExpression insensitive = secretLeakCompilePattern(QStringLiteral("(?i)abc"));
    require(insensitive.pattern() == QStringLiteral("abc"),
            "native prefix is removed exactly");
    require(insensitive.patternOptions().testFlag(QRegularExpression::CaseInsensitiveOption),
            "native prefix enables case insensitive option");
    require(insensitive.match(QStringLiteral("ABC")).hasMatch(),
            "case insensitive compiled pattern matches upper case");
    const QRegularExpression upperMarker = secretLeakCompilePattern(QStringLiteral("(?I)abc"));
    require(upperMarker.pattern() == QStringLiteral("abc")
                && upperMarker.patternOptions().testFlag(QRegularExpression::CaseInsensitiveOption),
            "prefix recognition uses native case insensitive startsWith");
    const QRegularExpression untrimmed = secretLeakCompilePattern(QStringLiteral(" (?i)abc"));
    require(untrimmed.pattern() == QStringLiteral(" (?i)abc")
                && !untrimmed.patternOptions().testFlag(QRegularExpression::CaseInsensitiveOption),
            "native compiler does not trim before prefix detection");
    // gui.exe:0x140054EF0 recognizes the whole `(?i)` marker, then removes
    // exactly four units before constructing the regular expression.
    const QRegularExpression bareMarker = secretLeakCompilePattern(QStringLiteral("(?i)"));
    require(bareMarker.pattern() == QStringLiteral("")
                && bareMarker.patternOptions().testFlag(QRegularExpression::CaseInsensitiveOption),
            "bare marker becomes an empty case insensitive pattern");
    return 0;
}
