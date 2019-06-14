#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "Utils/selector.h"
#include "Admin/admin.h"
#include "Proxy/proxy5nio.h"
#include "Utils/log.h"

int server_init(int port, int protocol, const struct fd_handler * handler);

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

const char *err_msg = NULL;
selector_status ss = SELECTOR_SUCCESS;
fd_selector selector = NULL;

const struct fd_handler proxyv5 = {
        .handle_read       = proxyv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
};

const struct fd_handler admin_handler = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
};

int
main(const int argc, const char **argv) {
    if (argc != 2) {
        printf("Parameter: <Proxy Server Port>");
        printf("Parameter: <Admin Server Port>");
        return 1;
    }

    unsigned proxy_port = atoi(argv[1]);
    //unsigned admin_port = atoi(argv[2]);

    // no tenemos nada que leer de stdin
    close(0);

    logger_init();

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    signal(SIGPIPE, SIG_IGN); // ignoro los SIGPIPE de esta manera ya que mac no soporta MSG_NOSIGNAL

    const struct selector_init conf = {
            .signal = SIGALRM,
            .select_timeout = {
                    .tv_sec  = 10,
                    .tv_nsec = 0,
            },
    };

    if (0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if (selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }

    int proxy_server = 0;//server_init(proxy_port, IPPROTO_TCP, &proxyv5);
    int admin_server = server_init(proxy_port, IPPROTO_TCP, &admin_handler);

    if (proxy_server  == -1|| admin_server == -1) {
        goto finally;
    }

    for (; !done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }

    if (err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
    finally:
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO
                ? strerror(errno)
                : selector_error(ss));
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    proxyv5_pool_destroy();

    if (proxy_server >= 0) {
        close(proxy_server);
    }
    return ret;
}


int server_init(int port, int protocol, const struct fd_handler * handler) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    const int server = socket(AF_INET, SOCK_STREAM, protocol);

    if (server < 0) {
        err_msg = "unable to create socket";
        return -1;
    }

    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));

    if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind socket";
        return -1;
    }

    if (listen(server, 1) < 0) {
        err_msg = "unable to listen";
        return -1;
    }

    if (selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        return -1;
    }

    ss = selector_register(selector, server, handler,
                           OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        return -1;
    }
    return  server;
}
