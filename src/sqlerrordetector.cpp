#include "sqlerrordetector.h"
#include <QRegularExpression>

namespace {

// MySQL error patterns
const QStringList mysqlPatterns = {
    QStringLiteral("SQL syntax.*?MySQL"),
    QStringLiteral("MySQLSyntaxErrorException"),
    QStringLiteral("valid MySQL result"),
    QStringLiteral("MySqlClient\\."),
    QStringLiteral("com\\.mysql\\.jdbc"),
    QStringLiteral("Zend_Db_(Adapter|Statement)_Mysqli_Exception"),
    QStringLiteral("check the manual that (corresponds to|fits) your (MySQL|Drizzle) server version"),
    QStringLiteral("Data too long for column .+? at"),
    QStringLiteral("ExtractValue does not exist"),
    QStringLiteral("\\[MySQL\\]\\[ODBC"),
    QStringLiteral("Unknown column '[^ ]+' in 'field list'"),
    QStringLiteral("SQLSTATE\\[\\d+\\]: Syntax")
};

// PostgreSQL error patterns
const QStringList postgresPatterns = {
    QStringLiteral("ERROR: parser: parse error at or near"),
    QStringLiteral("PostgreSQL query failed"),
    QStringLiteral("query failed: error:"),
    QStringLiteral("unterminated quoted string"),
    QStringLiteral("PostgreSQL.*?ERROR"),
    QStringLiteral("valid PostgreSQL result"),
    QStringLiteral("Npgsql\\."),
    QStringLiteral("PG::SyntaxError:"),
    QStringLiteral("org\\.postgresql\\.util\\.PSQLException")
};

// SQL Server error patterns
const QStringList mssqlPatterns = {
    QStringLiteral("Incorrect syntax near"),
    QStringLiteral("Unclosed quotation mark after the character string"),
    QStringLiteral("Microsoft OLE DB.*? SQL Server"),
    QStringLiteral("ODBC SQL Server Driver"),
    QStringLiteral("Microsoft SQL Native Client error '[0-9a-fA-F]{8}'"),
    QStringLiteral("\\bSQL Server[^<\"]+Driver"),
    QStringLiteral("System\\.Data\\.SqlClient\\.(SqlException|SqlConnection\\.OnError)"),
    QStringLiteral("ODBC Driver \\d+ for SQL Server"),
    QStringLiteral("\\bSQL Server[^<\"]+[0-9a-fA-F]{8}"),
    QStringLiteral("Driver.*? SQL[-_\\s]*Server"),
    QStringLiteral("OLE DB.*? SQL Server"),
    QStringLiteral("\\[SQL Server\\]")
};

// Oracle error patterns
const QStringList oraclePatterns = {
    QStringLiteral("\\bORA-\\d{4,5}"),
    QStringLiteral("\\[Oracle\\]\\[ODBC\\]\\[Ora\\]"),
    QStringLiteral("Zend_Db_(Adapter|Statement)_Oracle_Exception"),
    QStringLiteral("macromedia\\.jdbc\\.oracle"),
    QStringLiteral("oracle\\s?(exception|error)"),
    QStringLiteral("oracle\\.jdbc"),
    QStringLiteral("Pdo[./_\\\\](Oracle|OCI)"),
    QStringLiteral("Oracle.*?Driver")
};

// SQLite error patterns
const QStringList sqlitePatterns = {
    QStringLiteral("SQLite/JDBCDriver"),
    QStringLiteral("SQLite\\.Exception"),
    QStringLiteral("System\\.Data\\.SQLite\\.SQLiteException"),
    QStringLiteral("SQLITE_ERROR"),
    QStringLiteral("sqlite3\\.OperationalError"),
    QStringLiteral("\\[SQLITE_ERROR\\]"),
    QStringLiteral("SQL error or missing database"),
    QStringLiteral("unrecognized token:")
};

// Sybase error patterns
const QStringList sybasePatterns = {
    QStringLiteral("\\[Sybase\\]\\[ODBC"),
    QStringLiteral("Sybase message"),
    QStringLiteral("Sybase.*?Server message"),
    QStringLiteral("SybSQLException"),
    QStringLiteral("Sybase\\.Data\\.AseClient"),
    QStringLiteral("com\\.sybase\\.jdbc")
};

// Access/Jet error patterns
const QStringList accessPatterns = {
    QStringLiteral("Microsoft Access Driver"),
    QStringLiteral("JET Database Engine"),
    QStringLiteral("Microsoft JET Database"),
    QStringLiteral("\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]"),
    QStringLiteral("Access Database Engine")
};

// DB2 error patterns
const QStringList db2Patterns = {
    QStringLiteral("CLI Driver.*?DB2"),
    QStringLiteral("DB2 SQL error"),
    QStringLiteral("\\[IBM\\]\\[CLI Driver\\]"),
    QStringLiteral("com\\.ibm\\.db2\\.jcc"),
    QStringLiteral("SQLCODE=-\\d+, SQLSTATE=")
};

// Informix error patterns
const QStringList informixPatterns = {
    QStringLiteral("com\\.informix\\.jdbc"),
    QStringLiteral("Informix ODBC Driver"),
    QStringLiteral("\\[Informix\\]\\[ODBC"),
    QStringLiteral("SQLCODE=-\\d+")
};

// Firebird error patterns
const QStringList firebirdPatterns = {
    QStringLiteral("Dynamic SQL Error"),
    QStringLiteral("ibase_"),
    QStringLiteral("org\\.firebirdsql\\.jdbc"),
    QStringLiteral("Firebird ODBC Driver")
};

// H2 database error patterns
const QStringList h2Patterns = {
    QStringLiteral("org\\.h2\\.jdbc"),
    QStringLiteral("\\[42000-\\d+\\]"),
    QStringLiteral("org\\.h2\\.engine")
};

// HSQLDB error patterns
const QStringList hsqldbPatterns = {
    QStringLiteral("org\\.hsqldb\\.jdbc"),
    QStringLiteral("Unexpected token.*?in statement"),
    QStringLiteral("integrity constraint violation")
};

bool matchAnyPattern(const QString &text, const QStringList &patterns) {
    for (const QString &pattern : patterns) {
        QRegularExpression re(pattern, QRegularExpression::CaseInsensitiveOption);
        if (re.match(text).hasMatch()) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace


SqlErrorDetector::DatabaseType SqlErrorDetector::detect(const QString &responseText) const
{
    if (matchAnyPattern(responseText, mysqlPatterns)) {
        return DatabaseType::MySQL;
    }
    if (matchAnyPattern(responseText, postgresPatterns)) {
        return DatabaseType::PostgreSQL;
    }
    if (matchAnyPattern(responseText, mssqlPatterns)) {
        return DatabaseType::SQLServer;
    }
    if (matchAnyPattern(responseText, oraclePatterns)) {
        return DatabaseType::Oracle;
    }
    if (matchAnyPattern(responseText, sqlitePatterns)) {
        return DatabaseType::SQLite;
    }
    if (matchAnyPattern(responseText, sybasePatterns)) {
        return DatabaseType::Sybase;
    }
    if (matchAnyPattern(responseText, accessPatterns)) {
        return DatabaseType::Access;
    }
    if (matchAnyPattern(responseText, db2Patterns)) {
        return DatabaseType::DB2;
    }
    if (matchAnyPattern(responseText, informixPatterns)) {
        return DatabaseType::Informix;
    }
    if (matchAnyPattern(responseText, firebirdPatterns)) {
        return DatabaseType::Firebird;
    }
    if (matchAnyPattern(responseText, h2Patterns)) {
        return DatabaseType::H2;
    }
    if (matchAnyPattern(responseText, hsqldbPatterns)) {
        return DatabaseType::HSQLDB;
    }
    return DatabaseType::Unknown;
}

QString SqlErrorDetector::databaseName(DatabaseType type)
{
    switch (type) {
    case DatabaseType::MySQL: return QStringLiteral("MySQL");
    case DatabaseType::PostgreSQL: return QStringLiteral("PostgreSQL");
    case DatabaseType::SQLServer: return QStringLiteral("Microsoft SQL Server");
    case DatabaseType::Oracle: return QStringLiteral("Oracle");
    case DatabaseType::SQLite: return QStringLiteral("SQLite");
    case DatabaseType::Sybase: return QStringLiteral("Sybase");
    case DatabaseType::Access: return QStringLiteral("Microsoft Access");
    case DatabaseType::DB2: return QStringLiteral("IBM DB2");
    case DatabaseType::Informix: return QStringLiteral("Informix");
    case DatabaseType::Firebird: return QStringLiteral("Firebird");
    case DatabaseType::H2: return QStringLiteral("H2 Database");
    case DatabaseType::HSQLDB: return QStringLiteral("HSQLDB");
    default: return QStringLiteral("Unknown");
    }
}

bool SqlErrorDetector::hasSqlError(const QString &responseText) const
{
    return detect(responseText) != DatabaseType::Unknown;
}

QStringList SqlErrorDetector::getPatterns(DatabaseType type)
{
    switch (type) {
    case DatabaseType::MySQL: return mysqlPatterns;
    case DatabaseType::PostgreSQL: return postgresPatterns;
    case DatabaseType::SQLServer: return mssqlPatterns;
    case DatabaseType::Oracle: return oraclePatterns;
    case DatabaseType::SQLite: return sqlitePatterns;
    case DatabaseType::Sybase: return sybasePatterns;
    case DatabaseType::Access: return accessPatterns;
    case DatabaseType::DB2: return db2Patterns;
    case DatabaseType::Informix: return informixPatterns;
    case DatabaseType::Firebird: return firebirdPatterns;
    case DatabaseType::H2: return h2Patterns;
    case DatabaseType::HSQLDB: return hsqldbPatterns;
    default: return {};
    }
}

int SqlErrorDetector::severityLevel(DatabaseType type)
{
    // Higher severity for more common/exploitable databases
    switch (type) {
    case DatabaseType::MySQL:
    case DatabaseType::PostgreSQL:
    case DatabaseType::SQLServer:
    case DatabaseType::Oracle:
        return 3; // High
    case DatabaseType::SQLite:
    case DatabaseType::DB2:
        return 2; // Medium
    default:
        return 1; // Low
    }
}
