#pragma once
#include "parameterinjection.h"
#include "networkmanager.h"
#include "scanconfig.h"
#include "filelistquerystate.h"
#include "dircountconstrain.h"
#include <QUrlQuery>
#include <QStringList>
#include "scriptevent.h"

class Manipulator final : public QObject {
    Q_OBJECT
public:
    explicit Manipulator(QObject *parent = nullptr);
    // Source-level access to observed native component fields. Manager lifetime
    // remains owned by the caller here; native shared-owner wiring is pending.
    NetworkManager *networkManager = nullptr; // native pointer+16
    QSharedPointer<QList<ParameterExclusionRule>> exclusions; // native+32
    quint32 parameterCount = 0; // native+48
    quint32 vectorFlags = 31; // native+52
public slots:
    void scan(NetworkResponsePtr reply);
    void manipulate(ParameterInjectionPtr param, quint64 eventType, NetworkResponsePtr reply);
signals:
    void eventTriggered(Event event, NetworkResponsePtr reply, ParameterInjectionPtr parameter);
private:
    friend struct ManipulatorTestAccess;
    void detectBase64(const ParameterInjectionPtr &parameter);
    QString serializationType(const ParameterInjectionPtr &parameter);
    void queryParameters(const QUrlQuery &, const NetworkResponsePtr &, bool post,
                         const QList<QPair<QString, QString>> &packetItems);
    void cookieParameters(const NetworkResponsePtr &);
    void headerParameters(const NetworkResponsePtr &);
    void pathParameters(const NetworkResponsePtr &);
    QString pathSignature(const QUrl &) const;
    void postParameters(const NetworkResponsePtr &);
    void jsonParameters(const QByteArray &, const NetworkResponsePtr &);
    FileListQueryState m_queryState; // native+56
    QStringList m_cookieSignatures; // native+96
    QRegularExpression m_pathExpression; // native+120
    QStringList m_pathSignatures; // native+128
    DirCountConstrain m_headerConstraint; // native+152
    QRegularExpression m_jsonExpression; // native+208
};
