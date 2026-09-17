#pragma once

#include <QByteArray>
#include <QString>

// gui.exe:0x14015DEF0 / 0x14015E240 / 0x14015E590.
// These helpers are the recovered, stateless part of the Custom404Detector.
// The detector's request scheduling and response history remain separate.
namespace Custom404Similarity {

[[nodiscard]] QString normalizePageText(QString text);
[[nodiscard]] double score(QString first, QString second);
[[nodiscard]] double score(QByteArray first, QByteArray second);

} // namespace Custom404Similarity
