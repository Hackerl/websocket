#ifndef WEBSOCKET_WEBSOCKET_H
#define WEBSOCKET_WEBSOCKET_H

#include <event.h>
#include <map>
#include <string>
#include <common/interface.h>

class IWebSocketHandler {
public:
    virtual void onConnect() = 0;
};

class CWebSocket {
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
    void onHandshake(bufferevent *bev);
    void onChallenge(bufferevent *bev);

private:
    void handshake();

private:
    void setReadCallback(bufferevent_data_cb cb);

public:
    int mResponseCode{};
    std::map<std::string, std::string> mResponseHeaders;

private:
    int mPort{};
    std::string mUri;
    std::string mHost;
    std::string mScheme;

private:
    IWebSocketHandler *mHandler;

private:
    bufferevent *mBev{};
    evdns_base *mDnsBase;
    event_base *mEventBase;
};


#endif //WEBSOCKET_WEBSOCKET_H
