#include "websocket.h"
#include <event2/http.h>
#include <cstring>
#include <common/log.h>
#include <common/utils/string_helper.h>

constexpr auto KEY = "dGhlIHNhbXBsZSBub25jZQ==";
constexpr auto ACCEPT_KEY = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

CWebSocket::CWebSocket(IWebSocketHandler *handler, event_base *base, evdns_base *dnsBase) {
    mHandler = handler;
    mEventBase = base;
    mDnsBase = dnsBase;
}

bool CWebSocket::connect(const char *url) {
    evhttp_uri *uri = evhttp_uri_parse(url);

    if (!uri) {
        return false;
    }

    const char *scheme = evhttp_uri_get_scheme(uri);

    if (!scheme || (strcasecmp(scheme, "https") != 0 && strcasecmp(scheme, "http") != 0)) {
        evhttp_uri_free(uri);
        return false;
    }

    const char *host = evhttp_uri_get_host(uri);

    if (!host) {
        evhttp_uri_free(uri);
        return false;
    }

    int port = evhttp_uri_get_port(uri);

    if (port == -1) {
        port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;
    }

    const char *path = evhttp_uri_get_path(uri);

    if (strlen(path) == 0) {
        path = "/";
    }

    const char *query = evhttp_uri_get_query(uri);

    mHost = host;
    mPort = port;
    mScheme = scheme;
    mUri = !query ? path : CStringHelper::format("%s?%s", path, query);

    evhttp_uri_free(uri);

    struct stub {
        static void onRead(bufferevent *bev, void *ctx) {
            static_cast<CWebSocket *>(ctx)->onHandshake(bev);
        }

        static void onWrite(bufferevent *bev, void *ctx) {
            static_cast<CWebSocket *>(ctx)->onBufferWrite(bev);
        }

        static void onEvent(bufferevent *bev, short what, void *ctx) {
            static_cast<CWebSocket *>(ctx)->onBufferEvent(bev, what);
        }
    };

    mBev = bufferevent_socket_new(mEventBase, -1, BEV_OPT_CLOSE_ON_FREE);

    if (!mBev) {
        LOG_ERROR("new buffer failed");
        return false;
    }

    bufferevent_setcb(mBev, stub::onRead, stub::onWrite, stub::onEvent, this);

    if (bufferevent_enable(mBev, EV_READ | EV_WRITE) != 0) {
        LOG_ERROR("enable buffer failed");

        disconnect();
        return false;
    }

    if (bufferevent_socket_connect_hostname(mBev, mDnsBase, AF_UNSPEC, mHost.c_str(), mPort) != 0) {
        LOG_ERROR("connect failed: %s[%d]", mHost.c_str(), mPort);

        disconnect();
        return false;
    }

    return true;
}

void CWebSocket::disconnect() {
    LOG_INFO("disconnect");

    if (mBev) {
        bufferevent_free(mBev);
        mBev = nullptr;
    }
}

void CWebSocket::onBufferRead(bufferevent *bev) {
    evbuffer *input = bufferevent_get_input(bev);

    while (true) {
        if (evbuffer_get_length(input) < 2)
            return;

        char data[2] = {};

        if (evbuffer_copyout(input, data, sizeof(data)) != sizeof(data))
            break;
    }
}

void CWebSocket::onBufferWrite(bufferevent *bev) {

}

void CWebSocket::onBufferEvent(bufferevent *bev, short what) {
    if (what & BEV_EVENT_EOF) {
        LOG_INFO("buffer event EOF");
        disconnect();
    } else if (what & BEV_EVENT_ERROR) {
        LOG_ERROR("buffer event error: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        disconnect();
    } else if (what & BEV_EVENT_CONNECTED) {
        handshake();
    }
}

void CWebSocket::handshake() {
    LOG_INFO("handshake");

    evbuffer *output = bufferevent_get_output(mBev);

    evbuffer_add_printf(output, "GET %s HTTP/1.1\r\n", mUri.c_str());
    evbuffer_add_printf(output, "Host: %s:%d\r\n", mHost.c_str(), mPort);
    evbuffer_add_printf(output, "Upgrade: websocket\r\n");
    evbuffer_add_printf(output, "Connection: upgrade\r\n");
    evbuffer_add_printf(output, "Sec-WebSocket-Key: %s\r\n", KEY);
    evbuffer_add_printf(output, "Sec-WebSocket-Version: 13\r\n");
    evbuffer_add_printf(output, "Origin: %s://%s:%d\r\n", mScheme.c_str(), mHost.c_str(), mPort);
    evbuffer_add_printf(output, "\r\n");
}

void CWebSocket::onHandshake(bufferevent *bev) {
    evbuffer *input = bufferevent_get_input(bev);

    char *ptr = evbuffer_readln(input, nullptr, EVBUFFER_EOL_CRLF);

    if (!ptr)
        return;

    std::unique_ptr<char> line(ptr);
    std::vector<std::string> tokens = CStringHelper::split(line.get(), ' ');

    if (tokens.size() < 2) {
        LOG_ERROR("bad response: %s", line.get());

        disconnect();
        return;
    }

    if (!CStringHelper::toNumber(tokens[1], mResponseCode)) {
        LOG_ERROR("parse status code failed: %s", tokens[1].c_str());

        disconnect();
        return;
    }

    if (mResponseCode != 101) {
        LOG_ERROR("bad response status code: %d", mResponseCode);

        disconnect();
        return;
    }

    struct stub {
        static void onRead(bufferevent *bev, void *ctx) {
            static_cast<CWebSocket *>(ctx)->onChallenge(bev);
        }
    };

    setReadCallback(stub::onRead);
    onChallenge(bev);
}

void CWebSocket::onChallenge(bufferevent *bev) {
    evbuffer *input = bufferevent_get_input(bev);

    while (true) {
        char *ptr = evbuffer_readln(input, nullptr, EVBUFFER_EOL_CRLF);

        if (!ptr)
            return;

        std::unique_ptr<char> line(ptr);

        if (*line == '\0') {
            auto it = mResponseHeaders.find("Sec-WebSocket-Accept");

            if (it == mResponseHeaders.end()) {
                LOG_ERROR("websocket accept header not found");

                disconnect();
                break;
            }

            if (it->second != ACCEPT_KEY) {
                LOG_ERROR("websocket accept key error: %s", it->second.c_str());

                disconnect();
                break;
            }

            LOG_INFO("websocket connected");

            if (mHandler)
                mHandler->onConnect();

            struct stub {
                static void onRead(bufferevent *bev, void *ctx) {
                    static_cast<CWebSocket *>(ctx)->onBufferRead(bev);
                }
            };

            setReadCallback(stub::onRead);
            onBufferRead(bev);

            break;
        }

        std::vector<std::string> tokens = CStringHelper::split(line.get(), ':');

        if (tokens.size() < 2) {
            LOG_ERROR("bad header: %s", line.get());

            disconnect();
            break;
        }

        mResponseHeaders.insert({{tokens[0], CStringHelper::trimCopy(tokens[1])}});
    }
}

void CWebSocket::setReadCallback(bufferevent_data_cb cb) {
    void *context = nullptr;

    bufferevent_data_cb wcb = nullptr;
    bufferevent_event_cb ecb = nullptr;

    bufferevent_getcb(mBev, nullptr, &wcb, &ecb, &context);
    bufferevent_setcb(mBev, cb, wcb, ecb, context);
}
