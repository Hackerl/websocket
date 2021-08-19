#include "websocket.h"
#include <event2/http.h>
#include <cstring>
#include <memory>
#include <common/log.h>
#include <common/utils/random.h>
#include <common/utils/base64.h>
#include <openssl/sha.h>

constexpr auto TWO_BYTE_PAYLOAD_LENGTH = 126U;
constexpr auto EIGHT_BYTE_PAYLOAD_LENGTH = 127U;

constexpr auto MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#pragma pack(push, 1)

struct CHeader {
    unsigned int opcode : 4;
    unsigned int reserved3 : 1;
    unsigned int reserved2 : 1;
    unsigned int reserved1 : 1;
    unsigned int final : 1;
    unsigned int length : 7;
    unsigned int mask : 1;
};

#pragma pack(pop)


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

    if (!scheme || (strcasecmp(scheme, "wss") != 0 && strcasecmp(scheme, "ws") != 0)) {
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
        port = (strcasecmp(scheme, "ws") == 0) ? 80 : 443;
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
            static_cast<CWebSocket *>(ctx)->onStatus(bev);
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
        CHeader header = {};

        if (evbuffer_copyout(input, &header, sizeof(CHeader)) != sizeof(CHeader))
            break;

        if (header.mask) {
            disconnect();
            break;
        }

        unsigned long extended = 0;
        unsigned long length = header.length;

        if (length >= TWO_BYTE_PAYLOAD_LENGTH) {
            extended = length == EIGHT_BYTE_PAYLOAD_LENGTH ? 8 : 2;

            evbuffer_ptr pos = {};

            if (evbuffer_ptr_set(input, &pos, sizeof(CHeader), EVBUFFER_PTR_SET) != 0) {
                disconnect();
                break;
            }

            std::unique_ptr<unsigned char> value(new unsigned char[extended]());

            if (evbuffer_copyout_from(input, &pos, value.get(), extended) != extended)
                break;

            length = extended == 2 ? ntohs(*(uint16_t *)value.get()) : be64toh(*(uint64_t *)value.get());
        }

        if (evbuffer_get_length(input) < sizeof(CHeader) + extended + length)
            break;

        std::unique_ptr<unsigned char> buffer(new unsigned char[length]());

        if (evbuffer_drain(input, sizeof(CHeader) + extended) != 0 || evbuffer_remove(input, buffer.get(), length) != length) {
            LOG_ERROR("read buffer failed: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            disconnect();
            break;
        }

        if (!header.final && header.opcode != CONTINUATION) {
            mFragmentOpcode = (emOpcode)header.opcode;
            mFragments.insert(mFragments.end(), buffer.get(), buffer.get() + length);
            break;
        }

        if (header.final && header.opcode == CONTINUATION) {
            header.opcode = mFragmentOpcode;
            mFragments.insert(mFragments.end(), buffer.get(), buffer.get() + length);

            unsigned long size = mFragments.size();
            buffer = std::make_unique<unsigned char>(size);

            memcpy(buffer.get(), mFragments.data(), size);
            mFragments.clear();
        }

        switch ((emOpcode)header.opcode) {
            case CONTINUATION:
                mFragments.insert(mFragments.end(), buffer.get(), buffer.get() + length);
                break;

            case TEXT:
                mHandler->onTextMessage(this, {(const char *)buffer.get(), length});
                break;

            case BINARY:
                mHandler->onBinaryMessage(this, buffer.get(), length);
                break;

            case CLOSE:
                mHandler->onClose(
                        this,
                        *(unsigned short *)buffer.get(),
                        {
                            (const char *)buffer.get() + sizeof(unsigned short),
                            length - sizeof(unsigned short)
                        });
                break;

            case PING:
                mHandler->onPing(this, buffer.get(), length);
                break;

            case PONG:
                mHandler->onPong(this, buffer.get(), length);
                break;

            default:
                break;
        }
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

    char buffer[16] = {};

    CRandom().fill(buffer, sizeof(buffer));
    mKey = CBase64::encode((const unsigned char *)buffer, sizeof(buffer));

    evbuffer *output = bufferevent_get_output(mBev);

    evbuffer_add_printf(output, "GET %s HTTP/1.1\r\n", mUri.c_str());
    evbuffer_add_printf(output, "Host: %s:%d\r\n", mHost.c_str(), mPort);
    evbuffer_add_printf(output, "Upgrade: websocket\r\n");
    evbuffer_add_printf(output, "Connection: upgrade\r\n");
    evbuffer_add_printf(output, "Sec-WebSocket-Key: %s\r\n", mKey.c_str());
    evbuffer_add_printf(output, "Sec-WebSocket-Version: 13\r\n");
    evbuffer_add_printf(output, "Origin: %s://%s:%d\r\n", mScheme.c_str(), mHost.c_str(), mPort);
    evbuffer_add_printf(output, "\r\n");
}

void CWebSocket::onStatus(bufferevent *bev) {
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
            static_cast<CWebSocket *>(ctx)->onResponse(bev);
        }
    };

    setReadCallback(stub::onRead);
    onResponse(bev);
}

void CWebSocket::onResponse(bufferevent *bev) {
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

            std::string data = mKey + MAGIC;
            unsigned char digest[SHA_DIGEST_LENGTH] = {};

            SHA1((const unsigned char *)data.data(), data.size(), digest);
            std::string hash = CBase64::encode(digest, SHA_DIGEST_LENGTH);

            if (it->second != hash) {
                LOG_ERROR("websocket hash error");

                disconnect();
                break;
            }

            LOG_INFO("websocket connected");

            mHandler->onConnected(this);

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

void CWebSocket::sendText(const std::string &message) {

}

void CWebSocket::sendBinary(const unsigned char *buffer, unsigned long length) {

}

void CWebSocket::ping(const unsigned char *buffer, unsigned long length) {

}

void CWebSocket::pong(const unsigned char *buffer, unsigned long length) {

}

void CWebSocket::sendFrame(emOpcode opcode, const unsigned char *buffer, unsigned long length) {

}
