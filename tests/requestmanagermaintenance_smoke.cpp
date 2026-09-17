#include "requestmanagermaintenance.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);

    if (requestManagerShouldCollectReply(50, 3999, 1000, 0, 0))
        return 1;
    if (!requestManagerShouldCollectReply(51, 0, 0, 0, 0)
        || !requestManagerShouldCollectReply(50, 4000, 1000, 0, 0)
        || !requestManagerShouldCollectReply(0, 0, 0, 0, 0x100))
        return 2;
    if (requestManagerReplyTimedOut(91000, 1000, 90000)
        || !requestManagerReplyTimedOut(91001, 1000, 90000))
        return 3;
    return 0;
}
