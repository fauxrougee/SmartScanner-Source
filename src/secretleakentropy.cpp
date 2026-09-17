#include "secretleakentropy.h"

#include <QHash>

#include <cmath>

double secretLeakTextEntropy(const QString &text)
{
    // gui.exe:0x140054CF0.  The native first counts each QChar, then subtracts
    // log2(count / QString::size()) * (count / QString::size()) per entry.
    if (text.isEmpty())
        return 0.0;

    QHash<QChar, qsizetype> frequency;
    for (const QChar unit : text)
        ++frequency[unit];

    const double total = static_cast<double>(text.size());
    double entropy = 0.0;
    for (auto it = frequency.cbegin(); it != frequency.cend(); ++it) {
        const double probability = static_cast<double>(it.value()) / total;
        entropy -= std::log2(probability) * probability;
    }
    return entropy;
}

QString secretLeakContextLine(const QString &text, int offset)
{
    // gui.exe:0x140045A40.  Keep the native indexOf offset and the possibly
    // negative QString::mid length; in particular, an offset on '\n' has the
    // exact native result rather than a reconstructed special case.
    if (offset < 0 || offset >= text.size())
        return {};

    const qsizetype first = text.lastIndexOf(QLatin1Char('\n'), offset,
                                              Qt::CaseSensitive) + 1;
    qsizetype last = text.indexOf(QLatin1Char('\n'), offset, Qt::CaseSensitive);
    if (last == -1)
        last = text.size();
    return text.mid(first, last - first);
}

QRegularExpression secretLeakCompilePattern(const QString &rule)
{
    // gui.exe:0x140054EF0 copies the source unchanged, tests `(?i)` with Qt
    // case-sensitivity value 0 (CaseInsensitive), then removes exactly four
    // UTF-16 units and supplies PatternOption value 1 to the constructor.
    QString pattern(rule);
    QRegularExpression::PatternOptions options = QRegularExpression::NoPatternOption;
    if (pattern.startsWith(QStringLiteral("(?i)"), Qt::CaseInsensitive)) {
        options = QRegularExpression::CaseInsensitiveOption;
        pattern.remove(0, 4);
    }
    return QRegularExpression(pattern, options);
}
