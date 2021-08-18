#include "ws/websocket.h"
#include <event.h>
#include <event2/dns.h>
#include <common/log.h>

int main() {
    INIT_CONSOLE_LOG(INFO);

    event_base *base = event_base_new();
    evdns_base *dnsBase = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);

    CWebSocket ws(nullptr, base, dnsBase);

    ws.connect("URL");

    event_base_dispatch(base);

    event_base_free(base);
    evdns_base_free(dnsBase, 0);

    return 0;
}
