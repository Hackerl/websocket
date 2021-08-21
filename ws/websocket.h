#ifndef WEBSOCKET_WEBSOCKET_H
#define WEBSOCKET_WEBSOCKET_H

#include <event.h>
#include <map>
#include <vector>
#include <string>
#include <common/interface.h>
#include <common/utils/random.h>
#include <openssl/ssl.h>

enum emWebSocketState : unsigned int {
    CONNECTING,
    OPEN,
    CLOSING,
    CLOSED
};

enum emWebSocketOpcode : unsigned int {
    CONTINUATION = 0,
    TEXT = 1,
    BINARY = 2,
    CLOSE = 8,
    PING = 9,
    PONG = 10
};

class IWebSocket : public Interface {
public:
    virtual bool sendText(const std::string &message) = 0;
    virtual bool sendBinary(const unsigned char *buffer, unsigned long length) = 0;

public:
    virtual bool close(unsigned short code, const std::string &reason) = 0;

public:
    virtual bool ping(const unsigned char *buffer, unsigned long length) = 0;
    virtual bool pong(const unsigned char *buffer, unsigned long length) = 0;
};

class IWebSocketHandler : public Interface {
public:
    virtual void onConnected(IWebSocket *ws) = 0;
    virtual void onClose(IWebSocket *ws, unsigned short code, const std::string &reason) = 0;
    virtual void onClosed() = 0;

public:
    virtual void onText(IWebSocket *ws, const std::string& message) = 0;
    virtual void onBinary(IWebSocket *ws, const unsigned char *buffer, unsigned long length) = 0;

public:
    virtual void onPing(IWebSocket *ws, const unsigned char *buffer, unsigned long length) = 0;
    virtual void onPong(IWebSocket *ws, const unsigned char *buffer, unsigned long length) = 0;
};

class CWebSocket : public IWebSocket {
public:
    explicit CWebSocket(IWebSocketHandler *handler, event_base *base, evdns_base *dnsBase, SSL_CTX *ctx);
    ~CWebSocket() override;

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
    bool sendText(const std::string &message) override;
    bool sendBinary(const unsigned char *buffer, unsigned long length) override;

public:
    bool close(unsigned short code, const std::string &reason) override;

public:
    bool ping(const unsigned char *buffer, unsigned long length) override;
    bool pong(const unsigned char *buffer, unsigned long length) override;

private:
    bool sendFrame(emWebSocketOpcode opcode, const unsigned char *buffer, unsigned long length);

private:
    void handshake();

private:
    void setReadCallback(bufferevent_data_cb cb);

public:
    int mResponseCode{};
    std::map<std::string, std::string> mResponseHeaders;

public:
    emWebSocketState mState{};

private:
    emWebSocketOpcode mFragmentOpcode{};
    std::vector<unsigned char> mFragments;

private:
    int mPort{};
    std::string mUri;
    std::string mHost;
    std::string mScheme;
    std::string mKey;

private:
    CRandom mRandom;

private:
    bufferevent *mBev{};

private:
    evdns_base *mDnsBase;
    event_base *mEventBase;
    SSL_CTX *mSSLContext;
    IWebSocketHandler *mHandler;
};


#endif //WEBSOCKET_WEBSOCKET_H
