#include "manipulator.h"
#include "parameterinjection.h"
#include "injectionvector.h"
#include "urlencodedinjectionvector.h"
#include "parameterexclusion.h"
#include <QLoggingCategory>
#include <QMessageLogger>
#include <QDebug>
#include <QList>
#include <QPair>
#include <QSharedPointer>
#include <QString>
#include <QUrl>
#include <QUrlQuery>
#include <QVariant>

// Reconstruction of gui.exe:0x140112E90 (queryParameters).
// See decompiled/gui_manipulator_query_hexrays.c.

void Manipulator::queryParameters(const QUrlQuery &query,
                                  const NetworkResponsePtr &reply,
                                  bool post,
                                  const QList<QPair<QString, QString>> &packetItems)
{
    const QList<QPair<QString, QString>> items =
        query.queryItems(QUrl::PrettyDecoded);
    int index = -1;
    for (const QPair<QString, QString> &item : items) {
        ++index;
        if (item.first.isEmpty())
            continue;

        // acceptParameter is invoked before the vector is allocated.
        if (!m_queryState.acceptParameter(reply->url, item, packetItems, post))
            continue;

        const auto vector = QSharedPointer<UrlEncodedInjectionVector>::create(
            items, index);

        ParameterInjectionPtr param;
        if (post) {
            param = ParameterInjectionPtr(new PostParameterInjection(
                vector, item.first, item.second));
        } else {
            param = ParameterInjectionPtr(new QueryParameterInjection(
                vector, item.first, item.second));
        }

        if (exclusions && parameterExcluded(*exclusions, *param,
                                            reply->url.toString())) {
            continue;
        }

        const quint64 eventType = post ? 64 : 16;
        manipulate(param, eventType, reply);
    }
}
