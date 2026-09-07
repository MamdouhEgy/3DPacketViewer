// SPDX-License-Identifier: GPL-2.0-or-later
// Standalone dependency diagnostic: no Wireshark, plugin, capture, credential or AI request.
#include <QCoreApplication>
#include <QNetworkProxy>
#include <QUrl>
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const auto proxies
        = QNetworkProxyFactory::systemProxyForQuery(QNetworkProxyQuery(QUrl("https://opencode.ai/")));
    return proxies.isEmpty() ? 2 : 0;
}
