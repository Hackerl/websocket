#include "echo_client.h"
#include <zero/log.h>
#include <zero/encoding/hex.h>

CEchoClient::CEchoClient(event_base *base, evdns_base *dnsBase, SSL_CTX *ctx) : mWebSocket(this, base, dnsBase, ctx) {

}

void CEchoClient::onConnected(IWebSocket *ws) {
    LOG_INFO("websocket connected");
}

void CEchoClient::onClose(IWebSocket *ws, unsigned short code, const std::string &reason) {
    LOG_INFO("websocket close message: %hu %s", code, reason.c_str());
    ws->close(code, reason);
}

void CEchoClient::onClosed() {
    LOG_INFO("websocket closed");
}

void CEchoClient::onText(IWebSocket *ws, const std::string &message) {
    LOG_INFO("websocket text message: %s", message.c_str());
    ws->sendText(message);
}

void CEchoClient::onBinary(IWebSocket *ws, const unsigned char *buffer, unsigned long length) {
    LOG_INFO("websocket binary message: %s", zero::encoding::hex::encode(buffer, length).c_str());
    ws->sendBinary(buffer, length);
}

void CEchoClient::onPing(IWebSocket *ws, const unsigned char *buffer, unsigned long length) {
    LOG_INFO("websocket ping message: %s", zero::encoding::hex::encode(buffer, length).c_str());
    ws->pong(buffer, length);
}

void CEchoClient::onPong(IWebSocket *ws, const unsigned char *buffer, unsigned long length) {
    LOG_INFO("websocket pong message: %s", zero::encoding::hex::encode(buffer, length).c_str());
}

bool CEchoClient::start(const std::string &url) {
    if (!mWebSocket.connect(url.c_str())) {
        LOG_ERROR("websocket connect failed");
        return false;
    }

    return true;
}
