#include "custom404similarity.h"

#include <QRegularExpression>

namespace {

const QRegularExpression &wordSeparator()
{
    // gui.exe:0x140013540, static QRegularExpression at 0x1403689B0.
    static const QRegularExpression expression(QStringLiteral("\\s|\\\\|:|,|/|-|_"));
    return expression;
}

const QRegularExpression &htmlTag()
{
    // gui.exe:0x14015DEF0, static QRegularExpression at 0x1403689B8.
    static const QRegularExpression expression(QStringLiteral("<[^>]+?>"));
    return expression;
}

const QRegularExpression &symbolTail()
{
    // Literal transcribed from gui.exe:0x14015E18B.
    static const QRegularExpression expression(
        QStringLiteral("[!@#$%^&*()=`~,|?';\"}{\\]\\\\[][^\\s]*?"));
    return expression;
}

const QRegularExpression &styleBlock()
{
    // gui.exe:0x14015E1F3, PatternOption 1 (CaseInsensitiveOption).
    static const QRegularExpression expression(
        QStringLiteral("<style[^<]+?</style>"),
        QRegularExpression::CaseInsensitiveOption);
    return expression;
}

const QRegularExpression &scriptBlock()
{
    // gui.exe:0x14015E0B4, PatternOption 1 (CaseInsensitiveOption).
    static const QRegularExpression expression(
        QStringLiteral("<script[\\s\\S]+?</script>"),
        QRegularExpression::CaseInsensitiveOption);
    return expression;
}

} // namespace

namespace Custom404Similarity {

QString normalizePageText(QString text)
{
    // Exact replacement order from gui.exe:0x14015DF94..0x14015E05E.
    text.replace(styleBlock(), QStringLiteral(" "));
    text.replace(scriptBlock(), QStringLiteral(" "));
    text.replace(htmlTag(), QStringLiteral(" "));
    text.replace(symbolTail(), QStringLiteral(" "));
    return text.simplified();
}

double score(QString first, QString second)
{
    // gui.exe:0x14015E240 compares pre-normalization character counts first.
    const double firstLength = first.size();
    const double secondLength = second.size();
    if (firstLength <= secondLength) {
        if (secondLength - firstLength > secondLength / 1.2)
            return firstLength / (firstLength + secondLength);
    } else if (firstLength - secondLength > firstLength / 1.2) {
        return secondLength / (firstLength + secondLength);
    }

    first = normalizePageText(std::move(first));
    second = normalizePageText(std::move(second));
    if (first == second)
        return 100.0;

    const QList<QStringView> firstWords = QStringView(first).split(wordSeparator(), Qt::KeepEmptyParts);
    const QList<QStringView> secondWords = QStringView(second).split(wordSeparator(), Qt::KeepEmptyParts);
    const QList<QStringView> &shorter = firstWords.size() <= secondWords.size() ? firstWords : secondWords;
    const QList<QStringView> &longer = firstWords.size() <= secondWords.size() ? secondWords : firstWords;

    int matches = 0;
    for (const QStringView word : shorter) {
        for (const QStringView candidate : longer) {
            if (word == candidate) {
                ++matches;
                break;
            }
        }
    }
    return (static_cast<double>(matches) * 200.0) / (firstWords.size() + secondWords.size());
}

double score(QByteArray first, QByteArray second)
{
    // gui.exe:0x14015E590 mutates both QByteArray copies before QString conversion.
    first.replace('\0', ' ');
    second.replace('\0', ' ');
    return score(QString::fromUtf8(first), QString::fromUtf8(second));
}

} // namespace Custom404Similarity
