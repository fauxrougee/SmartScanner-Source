#ifndef SQLERRORDETECTOR_H
#define SQLERRORDETECTOR_H

#include <QString>
#include <QStringList>

class SqlErrorDetector
{
public:
    enum class DatabaseType {
        Unknown,
        MySQL,
        PostgreSQL,
        SQLServer,
        Oracle,
        SQLite,
        Sybase,
        Access,
        DB2,
        Informix,
        Firebird,
        H2,
        HSQLDB
    };
    SqlErrorDetector() = default;
    ~SqlErrorDetector() = default;

    DatabaseType detect(const QString &responseText) const;
    bool hasSqlError(const QString &responseText) const;

    static QString databaseName(DatabaseType type);
    static QStringList getPatterns(DatabaseType type);
    static int severityLevel(DatabaseType type);
};

#endif // SQLERRORDETECTOR_H
