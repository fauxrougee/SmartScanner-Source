#ifndef XSSDETECTOR_H
#define XSSDETECTOR_H

#include <QString>
#include <QStringList>
#include <QUrl>
#include <QMap>

class XssDetector
{
public:
    enum class XssType {
        None,
        ReflectedInBody,
        ReflectedInAttribute,
        ReflectedInScript,
        ReflectedInUrl,
        ReflectedInHeader,
        StoredXss,
        DomBased
    };
    enum class Context {
        HtmlBody,
        HtmlAttribute,
        JavaScript,
        Url,
        Css,
        Comment
    };
    XssDetector() = default;
    ~XssDetector() = default;

    XssType detectInResponse(const QString &responseBody, const QString &payload) const;
    XssType detectInUri(const QUrl &url) const;
    XssType detectInHeaders(const QMap<QString, QString> &headers) const;

    bool isVulnerable(const QString &responseBody, const QString &payload) const;
    Context determineContext(const QString &responseBody, int position) const;

    static QStringList getPayloads();
    static QStringList getEventHandlers();
    static QString escapeForContext(const QString &input, Context context);
    static int severityLevel(XssType type);
};

#endif // XSSDETECTOR_H
