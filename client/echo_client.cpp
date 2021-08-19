#include "echo_client.h"
#include <common/log.h>

CEchoClient::CEchoClient(event_base *base, evdns_base *dnsBase) : mWebSocket(this, base, dnsBase) {
    mBase = base;
}

void CEchoClient::onConnected(IWebSocket *ws) {
    LOG_INFO("websocket connected");
}

void CEchoClient::onClose(IWebSocket *ws, unsigned short code, const std::string &reason) {
    LOG_INFO("websocket close message: %%hu %s", code, reason.c_str());
    ws->close(code, reason);
}

void CEchoClient::onClosed() {
    LOG_INFO("websocket closed");
    event_base_loopbreak(mBase);
}

void CEchoClient::onText(IWebSocket *ws, const std::string &message) {
    LOG_INFO("websocket text message: %s", message.c_str());
    ws->sendText(message);
}

void CEchoClient::onBinary(IWebSocket *ws, const unsigned char *buffer, unsigned long length) {
    LOG_INFO("websocket binary message: %s", CBinascii::hexlify(buffer, length).c_str());
    ws->sendBinary(buffer, length);
}

void CEchoClient::onPing(IWebSocket *ws, const unsigned char *buffer, unsigned long length) {
    LOG_INFO("websocket ping message: %s", CBinascii::hexlify(buffer, length).c_str());
    ws->pong(buffer, length);
}

void CEchoClient::onPong(IWebSocket *ws, const unsigned char *buffer, unsigned long length) {
    LOG_INFO("websocket pong message: %s", CBinascii::hexlify(buffer, length).c_str());
}

bool CEchoClient::connect(const char *url) {
    return mWebSocket.connect(url);
}