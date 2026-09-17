#include "crawlerformexpressions.h"

namespace {

constexpr auto crawlerFormPatternOptions = QRegularExpression::CaseInsensitiveOption;

} // namespace

const QRegularExpression &crawlerFormExpression()
{
    // gui.exe:0x1400ED75F-0x1400ED78D.
    static const QRegularExpression expression(
        QStringLiteral(R"(<form(\s[^>]*?)*?>([\s\S]*?)</form>)"),
        crawlerFormPatternOptions);
    return expression;
}

const QRegularExpression &crawlerInputExpression()
{
    // gui.exe:0x1400ED7D8-0x1400ED806.
    static const QRegularExpression expression(QStringLiteral(R"(<input(\s[^>]*?)*?>)"),
                                                crawlerFormPatternOptions);
    return expression;
}

const QRegularExpression &crawlerSelectExpression()
{
    // gui.exe:0x1400ED847-0x1400ED875.
    static const QRegularExpression expression(
        QStringLiteral(R"(<select(\s[^>]*?)*?>([\s\S]*?)</select>)"),
        crawlerFormPatternOptions);
    return expression;
}

const QRegularExpression &crawlerTextareaExpression()
{
    // gui.exe:0x1400ED8B6-0x1400ED8E4.
    static const QRegularExpression expression(
        QStringLiteral(R"(<textarea(\s[^>]*?)*?>([\s\S]*?)</textarea>)"),
        crawlerFormPatternOptions);
    return expression;
}

const QRegularExpression &crawlerOptionExpression()
{
    // gui.exe:0x1400ED925-0x1400ED953.
    static const QRegularExpression expression(QStringLiteral(R"(<option(\s[^>]*?)*?>)"),
                                                crawlerFormPatternOptions);
    return expression;
}

const QRegularExpression &crawlerFormAttributeExpression()
{
    // gui.exe:0x1400ED991-0x1400ED9A6.
    static const QRegularExpression expression(
        QStringLiteral(R"(([^\s]+)\s*=\s*((?:"[^"]+")|(?:'[^']+')|(?:[^'">\s]+)))"),
        crawlerFormPatternOptions);
    return expression;
}
