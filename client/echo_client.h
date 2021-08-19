#ifndef WEBSOCKET_ECHO_CLIENT_H
#define WEBSOCKET_ECHO_CLIENT_H

#include <ws/websocket.h>

class CEchoClient : public IWebSocketHandler {
public:
    explicit CEchoClient(event_base *base, evdns_base *dnsBase);

public:
    void onConnected(IWebSocket *ws) override;
    void onClose(IWebSocket *ws, unsigned short code, const std::string &reason) override;
    void onClosed() override;

public:
    void onText(IWebSocket *ws, const std::string &message) override;
    void onBinary(IWebSocket *ws, const unsigned char *buffer, unsigned long length) override;

public:
    void onPing(IWebSocket *ws, const unsigned char *buffer, unsigned long length) override;
    void onPong(IWebSocket *ws, const unsigned char *buffer, unsigned long length) override;

public:
    bool connect(const char *url);

private:
    CWebSocket mWebSocket;

private:
    event_base *mBase;
};


#endif //WEBSOCKET_ECHO_CLIENT_H
