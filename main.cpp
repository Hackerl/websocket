#include "client/echo_client.h"
#include <common/log.h>
#include <common/cmdline.h>
#include <event2/dns.h>

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add<std::string>("url", 'u', "websocket url", true, "");
    parse.parse_check(argc, argv);

    INIT_CONSOLE_LOG(INFO);

    event_base *base = event_base_new();
    evdns_base *dnsBase = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);

    std::string url = parse.get<std::string>("url");

    CEchoClient client(base, dnsBase);

    if (!client.connect(url.c_str())) {
        LOG_ERROR("connect failed: %s", url.c_str());
        return -1;
    }

    event_base_dispatch(base);

    event_base_free(base);
    evdns_base_free(dnsBase, 0);

    return 0;
}
