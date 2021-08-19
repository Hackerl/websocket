#include "client/echo_client.h"
#include <common/log.h>
#include <common/cmdline.h>

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add<std::string>("url", 'u', "websocket url", true, "");
    parse.parse_check(argc, argv);

    INIT_CONSOLE_LOG(INFO);

    std::string url = parse.get<std::string>("url");

    CEchoClient client;

    if (!client.start(url))
        return -1;

    return 0;
}
