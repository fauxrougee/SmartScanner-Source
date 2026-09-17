#include "htmlnumericentity.h"

namespace {

bool isDigitForBase(QChar character, int base)
{
    if (character >= QLatin1Char('0') && character <= QLatin1Char('9'))
        return character.unicode() - u'0' < base;
    return base == 16
        && ((character >= QLatin1Char('A') && character <= QLatin1Char('F'))
            || (character >= QLatin1Char('a') && character <= QLatin1Char('f')));
}

bool isAsciiLetter(QChar character)
{
    return (character >= QLatin1Char('A') && character <= QLatin1Char('Z'))
        || (character >= QLatin1Char('a') && character <= QLatin1Char('z'));
}

bool recoveredNamedEntity(const QString &name, QChar *value)
{
    // gui.exe:0x1401514D0: values transcribed from its two static tables.
    // gui.exe:0x140159760 only forwards ASCII-letter candidates here; table
    // keys containing digits consequently remain unreachable natively.
    if (name == QLatin1String("amp") || name == QLatin1String("AMP")) {
        *value = QLatin1Char('&');
    } else if (name == QLatin1String("gt") || name == QLatin1String("GT")) {
        *value = QLatin1Char('>');
    } else if (name == QLatin1String("lt") || name == QLatin1String("LT")) {
        *value = QLatin1Char('<');
    } else if (name == QLatin1String("apos")) {
        *value = QLatin1Char('\'');
    // gui.exe:0x1401514D0, first accented entries of the 104-entry table.
    } else if (name == QLatin1String("aacute")) {
        *value = QChar(0x00E1);
    } else if (name == QLatin1String("Aacute")) {
        *value = QChar(0x00C1);
    } else if (name == QLatin1String("acirc")) {
        *value = QChar(0x00E2);
    } else if (name == QLatin1String("Acirc")) {
        *value = QChar(0x00C2);
    } else if (name == QLatin1String("aelig")) {
        *value = QChar(0x00E6);
    } else if (name == QLatin1String("AElig")) {
        *value = QChar(0x00C6);
    } else if (name == QLatin1String("agrave")) {
        *value = QChar(0x00E0);
    } else if (name == QLatin1String("Agrave")) {
        *value = QChar(0x00C0);
    } else if (name == QLatin1String("aring")) {
        *value = QChar(0x00E5);
    } else if (name == QLatin1String("Aring")) {
        *value = QChar(0x00C5);
    } else if (name == QLatin1String("atilde")) {
        *value = QChar(0x00E3);
    } else if (name == QLatin1String("Atilde")) {
        *value = QChar(0x00C3);
    } else if (name == QLatin1String("auml")) {
        *value = QChar(0x00E4);
    } else if (name == QLatin1String("Auml")) {
        *value = QChar(0x00C4);
    } else if (name == QLatin1String("ccedil")) {
        *value = QChar(0x00E7);
    } else if (name == QLatin1String("Ccedil")) {
        *value = QChar(0x00C7);
    } else if (name == QLatin1String("eacute")) {
        *value = QChar(0x00E9);
    } else if (name == QLatin1String("Eacute")) {
        *value = QChar(0x00C9);
    } else if (name == QLatin1String("ecirc")) {
        *value = QChar(0x00EA);
    } else if (name == QLatin1String("Ecirc")) {
        *value = QChar(0x00CA);
    } else if (name == QLatin1String("egrave")) {
        *value = QChar(0x00E8);
    } else if (name == QLatin1String("Egrave")) {
        *value = QChar(0x00C8);
    } else if (name == QLatin1String("eth")) {
        *value = QChar(0x00F0);
    } else if (name == QLatin1String("ETH")) {
        *value = QChar(0x00D0);
    } else if (name == QLatin1String("euml")) {
        *value = QChar(0x00EB);
    } else if (name == QLatin1String("Euml")) {
        *value = QChar(0x00CB);
    } else if (name == QLatin1String("iacute")) {
        *value = QChar(0x00ED);
    } else if (name == QLatin1String("Iacute")) {
        *value = QChar(0x00CD);
    } else if (name == QLatin1String("icirc")) {
        *value = QChar(0x00EE);
    } else if (name == QLatin1String("Icirc")) {
        *value = QChar(0x00CE);
    } else if (name == QLatin1String("igrave")) {
        *value = QChar(0x00EC);
    } else if (name == QLatin1String("Igrave")) {
        *value = QChar(0x00CC);
    } else if (name == QLatin1String("iuml")) {
        *value = QChar(0x00EF);
    } else if (name == QLatin1String("Iuml")) {
        *value = QChar(0x00CF);
    } else if (name == QLatin1String("ntilde")) {
        *value = QChar(0x00F1);
    } else if (name == QLatin1String("Ntilde")) {
        *value = QChar(0x00D1);
    } else if (name == QLatin1String("oacute")) {
        *value = QChar(0x00F3);
    } else if (name == QLatin1String("Oacute")) {
        *value = QChar(0x00D3);
    } else if (name == QLatin1String("ocirc")) {
        *value = QChar(0x00F4);
    } else if (name == QLatin1String("Ocirc")) {
        *value = QChar(0x00D4);
    } else if (name == QLatin1String("ograve")) {
        *value = QChar(0x00F2);
    } else if (name == QLatin1String("Ograve")) {
        *value = QChar(0x00D2);
    } else if (name == QLatin1String("oslash")) {
        *value = QChar(0x00F8);
    } else if (name == QLatin1String("Oslash")) {
        *value = QChar(0x00D8);
    } else if (name == QLatin1String("otilde")) {
        *value = QChar(0x00F5);
    } else if (name == QLatin1String("Otilde")) {
        *value = QChar(0x00D5);
    } else if (name == QLatin1String("ouml")) {
        *value = QChar(0x00F6);
    } else if (name == QLatin1String("Ouml")) {
        *value = QChar(0x00D6);
    } else if (name == QLatin1String("szlig")) {
        *value = QChar(0x00DF);
    } else if (name == QLatin1String("thorn")) {
        *value = QChar(0x00FE);
    } else if (name == QLatin1String("THORN")) {
        *value = QChar(0x00DE);
    } else if (name == QLatin1String("uacute")) {
        *value = QChar(0x00FA);
    } else if (name == QLatin1String("Uacute")) {
        *value = QChar(0x00DA);
    } else if (name == QLatin1String("ucirc")) {
        *value = QChar(0x00FB);
    } else if (name == QLatin1String("Ucirc")) {
        *value = QChar(0x00DB);
    } else if (name == QLatin1String("ugrave")) {
        *value = QChar(0x00F9);
    } else if (name == QLatin1String("Ugrave")) {
        *value = QChar(0x00D9);
    } else if (name == QLatin1String("uuml")) {
        *value = QChar(0x00FC);
    } else if (name == QLatin1String("Uuml")) {
        *value = QChar(0x00DC);
    } else if (name == QLatin1String("yacute")) {
        *value = QChar(0x00FD);
    } else if (name == QLatin1String("Yacute")) {
        *value = QChar(0x00DD);
    } else if (name == QLatin1String("yuml")) {
        *value = QChar(0x00FF);
    } else if (name == QLatin1String("quot") || name == QLatin1String("QUOT")) {
        *value = QLatin1Char('"');
    } else if (name == QLatin1String("brvbar")) {
        *value = QChar(0x00A6);
    } else if (name == QLatin1String("cent")) {
        *value = QChar(0x00A2);
    } else if (name == QLatin1String("curren")) {
        *value = QChar(0x00A4);
    } else if (name == QLatin1String("deg")) {
        *value = QChar(0x00B0);
    } else if (name == QLatin1String("frac14")) {
        *value = QChar(0x00BC);
    } else if (name == QLatin1String("frac34")) {
        *value = QChar(0x00BE);
    } else if (name == QLatin1String("iexcl")) {
        *value = QChar(0x00A1);
    } else if (name == QLatin1String("iquest")) {
        *value = QChar(0x00BF);
    } else if (name == QLatin1String("laquo")) {
        *value = QChar(0x00AB);
    } else if (name == QLatin1String("micro")) {
        *value = QChar(0x00B5);
    } else if (name == QLatin1String("not")) {
        *value = QChar(0x00AC);
    } else if (name == QLatin1String("ordf")) {
        *value = QChar(0x00AA);
    } else if (name == QLatin1String("ordm")) {
        *value = QChar(0x00BA);
    } else if (name == QLatin1String("para")) {
        *value = QChar(0x00B6);
    } else if (name == QLatin1String("pound")) {
        *value = QChar(0x00A3);
    } else if (name == QLatin1String("raquo")) {
        *value = QChar(0x00BB);
    } else if (name == QLatin1String("sect")) {
        *value = QChar(0x00A7);
    } else if (name == QLatin1String("shy")) {
        *value = QChar(0x00AD);
    } else if (name == QLatin1String("times")) {
        *value = QChar(0x00D7);
    } else if (name == QLatin1String("yen")) {
        *value = QChar(0x00A5);
    } else if (name == QLatin1String("cedil") || name == QLatin1String("Cedilla")) {
        *value = QChar(0x00B8);
    } else if (name == QLatin1String("middot") || name == QLatin1String("centerdot")
               || name == QLatin1String("CenterDot")) {
        *value = QChar(0x00B7);
    } else if (name == QLatin1String("reg") || name == QLatin1String("REG")
               || name == QLatin1String("circledR")) {
        *value = QChar(0x00AE);
    } else if (name == QLatin1String("copy") || name == QLatin1String("COPY")) {
        *value = QChar(0x00A9);
    } else if (name == QLatin1String("acute") || name == QLatin1String("DiacriticalAcute")) {
        *value = QChar(0x00B4);
    } else if (name == QLatin1String("divide") || name == QLatin1String("div")) {
        *value = QChar(0x00F7);
    } else if (name == QLatin1String("uml") || name == QLatin1String("Dot")
               || name == QLatin1String("die") || name == QLatin1String("DoubleDot")) {
        *value = QChar(0x00A8);
    } else if (name == QLatin1String("NonBreakingSpace")) {
        *value = QLatin1Char(' ');
    } else if (name == QLatin1String("pm") || name == QLatin1String("PlusMinus")) {
        *value = QChar(0x00B1);
    } else if (name == QLatin1String("strns")) {
        *value = QChar(0x00AF);
    } else if (name == QLatin1String("equals")) {
        *value = QLatin1Char('=');
    } else if (name == QLatin1String("quest")) {
        *value = QLatin1Char('?');
    } else if (name == QLatin1String("ast") || name == QLatin1String("midast")) {
        *value = QLatin1Char('*');
    } else if (name == QLatin1String("bsol")) {
        *value = QLatin1Char('\\');
    } else if (name == QLatin1String("colon")) {
        *value = QLatin1Char(':');
    } else if (name == QLatin1String("comma")) {
        *value = QLatin1Char(',');
    } else if (name == QLatin1String("commat")) {
        *value = QLatin1Char('@');
    } else if (name == QLatin1String("dollar")) {
        *value = QLatin1Char('$');
    } else if (name == QLatin1String("excl")) {
        *value = QLatin1Char('!');
    } else if (name == QLatin1String("grave") || name == QLatin1String("DiacriticalGrave")) {
        *value = QLatin1Char('`');
    } else if (name == QLatin1String("Hat")) {
        *value = QLatin1Char('^');
    } else if (name == QLatin1String("lowbar") || name == QLatin1String("UnderBar")) {
        *value = QLatin1Char('_');
    } else if (name == QLatin1String("lpar")) {
        *value = QLatin1Char('(');
    } else if (name == QLatin1String("lsqb") || name == QLatin1String("lbrack")) {
        *value = QLatin1Char('[');
    } else if (name == QLatin1String("NewLine")) {
        *value = QLatin1Char('\n');
    } else if (name == QLatin1String("percnt")) {
        *value = QLatin1Char('%');
    } else if (name == QLatin1String("period")) {
        *value = QLatin1Char('.');
    } else if (name == QLatin1String("plus")) {
        *value = QLatin1Char('+');
    } else if (name == QLatin1String("rcub") || name == QLatin1String("rbrace")) {
        *value = QLatin1Char('}');
    } else if (name == QLatin1String("rpar")) {
        *value = QLatin1Char(')');
    } else if (name == QLatin1String("rsqb") || name == QLatin1String("rbrack")) {
        *value = QLatin1Char(']');
    } else if (name == QLatin1String("semi")) {
        *value = QLatin1Char(';');
    } else if (name == QLatin1String("sol")) {
        *value = QLatin1Char('/');
    } else if (name == QLatin1String("Tab")) {
        *value = QLatin1Char('\t');
    } else if (name == QLatin1String("verbar") || name == QLatin1String("vert")
               || name == QLatin1String("VerticalLine")) {
        *value = QLatin1Char('|');
    } else {
        return false;
    }
    return true;
}

} // namespace

QString decodeNumericHtmlCharacterReferences(QString input)
{
    // gui.exe:0x140159760. The native iterates UTF-8 bytes, parses '#'
    // references in decimal or lower-case 'x' hexadecimal form, creates a
    // QString from one QChar, and consumes an optional trailing semicolon.
    qsizetype searchOffset = 0;
    while (true) {
        const qsizetype ampersand = input.indexOf(QLatin1Char('&'), searchOffset);
        if (ampersand < 0 || ampersand + 1 >= input.size())
            break;
        if (input.at(ampersand + 1) != QLatin1Char('#')) {
            searchOffset = ampersand + 1;
            continue;
        }

        qsizetype digitsBegin = ampersand + 2;
        int base = 10;
        if (digitsBegin < input.size() && input.at(digitsBegin) == QLatin1Char('x')) {
            base = 16;
            ++digitsBegin;
        }
        qsizetype digitsEnd = digitsBegin;
        while (digitsEnd < input.size() && isDigitForBase(input.at(digitsEnd), base))
            ++digitsEnd;

        // QByteArray::toInt on the native's accumulated digit buffer yields
        // zero when no valid digit was collected. Its QString(QChar) path
        // consequently preserves the observed 16-bit conversion behavior.
        bool conversionOk = false;
        const int codePoint = input.mid(digitsBegin, digitsEnd - digitsBegin)
                                  .toInt(&conversionOk, base);
        const QString replacement(QChar(static_cast<ushort>(conversionOk ? codePoint : 0)));
        qsizetype consumedEnd = digitsEnd;
        if (consumedEnd < input.size() && input.at(consumedEnd) == QLatin1Char(';'))
            ++consumedEnd;
        input.replace(ampersand, consumedEnd - ampersand, replacement);
        searchOffset = ampersand + replacement.size();
    }
    return input;
}

QString decodeHtmlCharacterReferences(QString input)
{
    input = decodeNumericHtmlCharacterReferences(std::move(input));

    qsizetype searchOffset = 0;
    while (true) {
        const qsizetype ampersand = input.indexOf(QLatin1Char('&'), searchOffset);
        if (ampersand < 0 || ampersand + 1 >= input.size()
            || !isAsciiLetter(input.at(ampersand + 1)))
        {
            if (ampersand < 0)
                break;
            searchOffset = ampersand + 1;
            continue;
        }

        qsizetype end = ampersand + 1;
        const qsizetype limit = qMin(input.size(), ampersand + 32);
        while (end < limit && isAsciiLetter(input.at(end)))
            ++end;
        QChar value;
        if (!recoveredNamedEntity(input.mid(ampersand + 1, end - ampersand - 1), &value)) {
            searchOffset = ampersand + 1;
            continue;
        }
        if (end < input.size() && input.at(end) == QLatin1Char(';'))
            ++end;
        input.replace(ampersand, end - ampersand, QString(value));
        searchOffset = ampersand + 1;
    }
    return input;
}
