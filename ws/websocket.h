#ifndef WEBSOCKET_WEBSOCKET_H
#define WEBSOCKET_WEBSOCKET_H

#include <event.h>
#include <map>
#include <vector>
#include <string>
#include <common/interface.h>

enum emOpcode : unsigned int {
    CONTINUATION = 0,
    TEXT = 1,
    BINARY = 2,
    CLOSE = 8,
    PING = 9,
    PONG = 10
};

class IWebSocket : public Interface {
public:
    virtual void sendText(const std::string &message) = 0;
    virtual void sendBinary(const unsigned char *buffer, unsigned long length) = 0;

public:
    virtual void ping(const unsigned char *buffer, unsigned long length) = 0;
    virtual void pong(const unsigned char *buffer, unsigned long length) = 0;
};

class IWebSocketHandler : public Interface {
public:
    virtual void onConnected(IWebSocket *ws) = 0;
    virtual void onClose(IWebSocket *ws, unsigned short code, const std::string &reason) = 0;

public:
    virtual void onTextMessage(IWebSocket *ws, const std::string& message) = 0;
    virtual void onBinaryMessage(IWebSocket *ws, const unsigned char *buffer, unsigned long length) = 0;

public:
    virtual void onPing(IWebSocket *ws, const unsigned char *buffer, unsigned long length) = 0;
    virtual void onPong(IWebSocket *ws, const unsigned char *buffer, unsigned long length) = 0;
};

class CWebSocket : public IWebSocket {
public:
    explicit CWebSocket(IWebSocketHandler *handler, event_base *base, evdns_base *dnsBase = nullptr);

public:
    bool connect(const char *url);
    void disconnect();

public:
    void onBufferRead(bufferevent *bev);
    void onBufferWrite(bufferevent *bev);
    void onBufferEvent(bufferevent *bev, short what);

public:
    void onStatus(bufferevent *bev);
    void onResponse(bufferevent *bev);

public:
    void sendText(const std::string &message) override;
    void sendBinary(const unsigned char *buffer, unsigned long length) override;

public:
    void ping(const unsigned char *buffer, unsigned long length) override;
    void pong(const unsigned char *buffer, unsigned long length) override;

private:
    void sendFrame(emOpcode opcode, const unsigned char *buffer, unsigned long length);

private:
    void handshake();

private:
    void setReadCallback(bufferevent_data_cb cb);

public:
    int mResponseCode{};
    std::map<std::string, std::string> mResponseHeaders;

private:
    emOpcode mFragmentOpcode{};
    std::vector<unsigned char> mFragments;

private:
    int mPort{};
    std::string mUri;
    std::string mHost;
    std::string mScheme;
    std::string mKey;

private:
    IWebSocketHandler *mHandler;

private:
    bufferevent *mBev{};
    evdns_base *mDnsBase;
    event_base *mEventBase;
};


#endif //WEBSOCKET_WEBSOCKET_H
