#include "websocket.h"
#include <event2/http.h>
#include <event2/bufferevent_ssl.h>
#include <cstring>
#include <zero/log.h>
#include <zero/encoding/base64.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

constexpr auto SWITCHING_PROTOCOLS_STATUS = 101;
constexpr auto MASKING_KEY_LENGTH = 4;

constexpr auto TWO_BYTE_PAYLOAD_LENGTH = 126U;
constexpr auto EIGHT_BYTE_PAYLOAD_LENGTH = 127U;

constexpr auto MAX_SINGLE_BYTE_PAYLOAD_LENGTH = 125U;
constexpr auto MAX_TWO_BYTE_PAYLOAD_LENGTH = UINT16_MAX;

constexpr auto WEBSOCKET_SCHEME = "ws";
constexpr auto WEBSOCKET_SECURE_SCHEME = "wss";
constexpr auto WEBSOCKET_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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


CWebSocket::CWebSocket(IWebSocketHandler *handler, event_base *base, evdns_base *dnsBase, SSL_CTX *ctx) {
    mHandler = handler;
    mEventBase = base;
    mDnsBase = dnsBase;
    mSSLContext = ctx;
}

CWebSocket::~CWebSocket() {
    if (mBev) {
        bufferevent_free(mBev);
        mBev = nullptr;
    }
}

bool CWebSocket::connect(const char *url) {
    evhttp_uri *uri = evhttp_uri_parse(url);

    if (!uri) {
        return false;
    }

    const char *scheme = evhttp_uri_get_scheme(uri);

    if (!scheme || (strcasecmp(scheme, WEBSOCKET_SCHEME) != 0 && strcasecmp(scheme, WEBSOCKET_SECURE_SCHEME) != 0)) {
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
        port = (strcasecmp(scheme, WEBSOCKET_SCHEME) == 0) ? 80 : 443;
    }

    const char *path = evhttp_uri_get_path(uri);

    if (strlen(path) == 0) {
        path = "/";
    }

    const char *query = evhttp_uri_get_query(uri);

    mHost = host;
    mPort = port;
    mScheme = scheme;
    mUri = !query ? path : zero::strings::format("%s?%s", path, query);

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

    if (mScheme == WEBSOCKET_SCHEME) {
        mBev = bufferevent_socket_new(mEventBase, -1, BEV_OPT_CLOSE_ON_FREE);
    } else {
        SSL *ssl = SSL_new(mSSLContext);

        if (!ssl) {
            LOG_ERROR("new ssl failed: %s", ERR_error_string(ERR_get_error(), nullptr));
            return false;
        }

        SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

        if (!SSL_set1_host(ssl, mHost.c_str())) {
            LOG_ERROR("set ssl hostname failed: %s", ERR_error_string(ERR_get_error(), nullptr));
            SSL_free(ssl);
            return false;
        }

        SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);

        mBev = bufferevent_openssl_socket_new(
                mEventBase,
                -1,
                ssl,
                BUFFEREVENT_SSL_CONNECTING,
                BEV_OPT_CLOSE_ON_FREE
                );
    }

    if (!mBev) {
        LOG_ERROR("new buffer event failed");
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

    mState = CONNECTING;

    return true;
}

void CWebSocket::disconnect() {
    LOG_INFO("disconnect");

    if (mBev) {
        bufferevent_free(mBev);
        mBev = nullptr;
    }

    mFragments.clear();
    mHandler->onClosed();
}

void CWebSocket::onBufferRead(bufferevent *bev) {
    evbuffer *input = bufferevent_get_input(bev);

    while (true) {
        CHeader header = {};

        if (evbuffer_copyout(input, &header, sizeof(CHeader)) != sizeof(CHeader))
            break;

        if (header.mask) {
            LOG_ERROR("masked server frame not supported");
            disconnect();
            break;
        }

        unsigned long extendedBytes = 0;
        unsigned long length = header.length;

        if (length >= TWO_BYTE_PAYLOAD_LENGTH) {
            extendedBytes = length == EIGHT_BYTE_PAYLOAD_LENGTH ? 8 : 2;

            evbuffer_ptr pos = {};

            if (evbuffer_ptr_set(input, &pos, sizeof(CHeader), EVBUFFER_PTR_SET) != 0) {
                disconnect();
                break;
            }

            std::unique_ptr<unsigned char> extended(new unsigned char[extendedBytes]());

            if (evbuffer_copyout_from(input, &pos, extended.get(), extendedBytes) != extendedBytes)
                break;

            length = extendedBytes == 2 ? ntohs(*(uint16_t *)extended.get()) : be64toh(*(uint64_t *)extended.get());
        }

        if (evbuffer_get_length(input) < sizeof(CHeader) + extendedBytes + length)
            break;

        std::unique_ptr<unsigned char> buffer(new unsigned char[length]());

        if (evbuffer_drain(input, sizeof(CHeader) + extendedBytes) != 0 || evbuffer_remove(input, buffer.get(), length) != length) {
            LOG_ERROR("read buffer failed: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            disconnect();
            break;
        }

        if (!header.final && header.opcode != CONTINUATION) {
            mFragmentOpcode = (emWebSocketOpcode)header.opcode;
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

        switch ((emWebSocketOpcode)header.opcode) {
            case CONTINUATION:
                mFragments.insert(mFragments.end(), buffer.get(), buffer.get() + length);
                break;

            case TEXT:
                mHandler->onText(this, {(const char *) buffer.get(), length});
                break;

            case BINARY:
                mHandler->onBinary(this, buffer.get(), length);
                break;

            case CLOSE:
                if (mState == OPEN) {
                    mState = CLOSING;
                } else if (mState == CLOSING) {
                    mState = CLOSED;
                    disconnect();
                    break;
                }

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

    for (char &i : buffer) {
        i = static_cast<char>(mRandom() & 0xff);
    }

    mKey = zero::encoding::base64::encode((const unsigned char *)buffer, sizeof(buffer));

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
    std::vector<std::string> tokens = zero::strings::split(line.get(), " ");

    if (tokens.size() < 2) {
        LOG_ERROR("bad response: %s", line.get());
        disconnect();
        return;
    }

    if (!zero::strings::toNumber(tokens[1], mResponseCode)) {
        LOG_ERROR("parse status code failed: %s", tokens[1].c_str());
        disconnect();
        return;
    }

    if (mResponseCode != SWITCHING_PROTOCOLS_STATUS) {
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

            std::string data = mKey + WEBSOCKET_MAGIC;
            unsigned char digest[SHA_DIGEST_LENGTH] = {};

            SHA1((const unsigned char *)data.data(), data.size(), digest);
            std::string hash = zero::encoding::base64::encode(digest, SHA_DIGEST_LENGTH);

            if (it->second != hash) {
                LOG_ERROR("websocket hash error");
                disconnect();
                break;
            }

            LOG_INFO("websocket opened");

            mState = OPEN;
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

        std::vector<std::string> tokens = zero::strings::split(line.get(), ":");

        if (tokens.size() < 2) {
            LOG_ERROR("bad header: %s", line.get());
            disconnect();
            break;
        }

        mResponseHeaders.insert({{tokens[0], zero::strings::trim(tokens[1])}});
    }
}

void CWebSocket::setReadCallback(bufferevent_data_cb cb) {
    void *context = nullptr;

    bufferevent_data_cb wcb = nullptr;
    bufferevent_event_cb ecb = nullptr;

    bufferevent_getcb(mBev, nullptr, &wcb, &ecb, &context);
    bufferevent_setcb(mBev, cb, wcb, ecb, context);
}

bool CWebSocket::sendText(const std::string &message) {
    if (mState != OPEN) {
        LOG_WARNING("send text frame in %u state", mState);
        return false;
    }

    return sendFrame(TEXT, (const unsigned char *)message.data(), message.length());
}

bool CWebSocket::sendBinary(const unsigned char *buffer, unsigned long length) {
    if (mState != OPEN) {
        LOG_WARNING("send binary frame in %u state", mState);
        return false;
    }

    return sendFrame(BINARY, buffer, length);
}

bool CWebSocket::close(unsigned short code, const std::string &reason) {
    switch (mState) {
        case OPEN:
            mState = CLOSING;
            break;

        case CLOSING:
            mState = CLOSED;
            break;

        default:
            LOG_WARNING("send close frame in %u state", mState);
            return false;
    }

    unsigned long length = sizeof(unsigned short) + reason.length();
    std::unique_ptr<unsigned char> buffer(new unsigned char[length]());

    memcpy(buffer.get(), &code, sizeof(unsigned short));
    memcpy(buffer.get(), reason.data(), reason.length());

    return sendFrame(CLOSE, buffer.get(), length);
}

bool CWebSocket::ping(const unsigned char *buffer, unsigned long length) {
    if (mState != OPEN) {
        LOG_WARNING("send ping frame in %u state", mState);
        return false;
    }

    return sendFrame(PING, buffer, length);
}

bool CWebSocket::pong(const unsigned char *buffer, unsigned long length) {
    if (mState != OPEN) {
        LOG_WARNING("send pong frame in %u state", mState);
        return false;
    }

    return sendFrame(PONG, buffer, length);
}

bool CWebSocket::sendFrame(emWebSocketOpcode opcode, const unsigned char *buffer, unsigned long length) {
    if (!mBev) {
        LOG_WARNING("buffer event has been destroyed");
        return false;
    }

    CHeader header = {};

    header.opcode = opcode;
    header.final = 1;
    header.mask = 1;

    unsigned long extendedBytes = 0;
    std::unique_ptr<unsigned char> extended;

    if (length > MAX_TWO_BYTE_PAYLOAD_LENGTH) {
        extendedBytes = 8;
        header.length = EIGHT_BYTE_PAYLOAD_LENGTH;

        uint64_t extendedLength = htobe64(length);
        extended = std::make_unique<unsigned char>(extendedBytes);

        memcpy(extended.get(), &extendedLength, sizeof(uint64_t));
    } else if (length > MAX_SINGLE_BYTE_PAYLOAD_LENGTH) {
        extendedBytes = 2;
        header.length = TWO_BYTE_PAYLOAD_LENGTH;

        uint16_t extendedLength = htons(length);
        extended = std::make_unique<unsigned char>(extendedBytes);

        memcpy(extended.get(), &extendedLength, sizeof(uint16_t));
    } else {
        header.length = length;
    }

    bufferevent_write(mBev, &header, sizeof(CHeader));

    if (extendedBytes) {
        bufferevent_write(mBev, extended.get(), extendedBytes);
    }

    unsigned char maskingKey[MASKING_KEY_LENGTH] = {};

    for (unsigned char &i : maskingKey) {
        i = static_cast<unsigned char>(mRandom() & 0xff);
    }

    bufferevent_write(mBev, maskingKey, MASKING_KEY_LENGTH);

    for (unsigned long i = 0; i < length; i++) {
        unsigned char c = buffer[i] ^ maskingKey[i % 4];
        bufferevent_write(mBev, &c, 1);
    }

    return true;
}
