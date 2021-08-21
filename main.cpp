#include "client/echo_client.h"
#include <common/log.h>
#include <common/cmdline.h>
#include <event2/dns.h>
#include <openssl/err.h>

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add<std::string>("url", 'u', "websocket url", true, "");
    parse.parse_check(argc, argv);

    INIT_CONSOLE_LOG(INFO);

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());

    if (!ctx) {
        LOG_ERROR("new ssl context failed: %s", ERR_error_string(ERR_get_error(), nullptr));
        return -1;
    }

    X509_STORE *store = SSL_CTX_get_cert_store(ctx);

    if (X509_STORE_set_default_paths(store) != 1) {
        LOG_ERROR("set ssl store failed: %s", ERR_error_string(ERR_get_error(), nullptr));
        SSL_CTX_free(ctx);
        return -1;
    }

    event_base *base = event_base_new();

    if (!base) {
        LOG_ERROR("new event base failed: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        SSL_CTX_free(ctx);
        return -1;
    }

    evdns_base *dnsBase = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);

    if (!dnsBase) {
        LOG_ERROR("new dns base failed: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

        SSL_CTX_free(ctx);
        event_base_free(base);

        return -1;
    }

    std::string url = parse.get<std::string>("url");

    CEchoClient client(base, dnsBase, ctx);

    if (!client.start(url)) {
        LOG_ERROR("client start failed: %s", url.c_str());

        SSL_CTX_free(ctx);

        event_base_free(base);
        evdns_base_free(dnsBase, 0);

        return -1;
    }

    event_base_dispatch(base);

    SSL_CTX_free(ctx);

    event_base_free(base);
    evdns_base_free(dnsBase, 0);

    return 0;
}
