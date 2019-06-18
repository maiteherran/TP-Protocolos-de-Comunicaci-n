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
#include <arpa/inet.h>
#include "Utils/selector.h"
#include "Admin/admin_nio.h"
#include "Proxy/proxy_nio.h"
#include "Utils/log.h"
#include "Proxy/metrics.h"
#include "Proxy/config.h"
#include "Utils/server_arguments.h"

metrics                proxy_metrics;
conf                   proxy_configurations;
extern server_args_ptr args;

int server_init(int port, char *address, int protocol, const struct fd_handler *handler);

void metrics_init();

void conf_init(char *media_types, char *transf_p, char *error_f);

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

const char      *err_msg = NULL;
selector_status ss       = SELECTOR_SUCCESS;
fd_selector     selector = NULL;

const struct fd_handler proxy_handler = {
        .handle_read       = proxy_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
        .handle_timeout    = NULL
};

const struct fd_handler admin_handler = {
        .handle_read       = hpcp_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
        .handle_timeout    = NULL,
};

int
main(const int argc, const char **argv) {
    // no tenemos nada que leer de stdin
    close(0);

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

    args = read_arguments(argc, argv);
    logger_init();
    metrics_init();
    conf_init(args->media_types, args->cmd, args->error_file);

    int proxy_server = server_init(args->http_port, args->http_address, IPPROTO_TCP, &proxy_handler);
    int admin_server = server_init(args->admin_port, args->admin_address, IPPROTO_TCP,
                                   &admin_handler); // TODO: pasar a IPPROTO_SCTP

    if (proxy_server == -1 || admin_server == -1) {
        goto finally;
    }

    for (; !done;) {
        err_msg = NULL;
        ss      = selector_select(selector);
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

    proxy_pool_destroy();

    if (proxy_server >= 0) {
        close(proxy_server);
    }
    return ret;
}


int server_init(int port, char *address, int protocol, const struct fd_handler *handler) {
    struct sockaddr_in addr;
    struct addrinfo    hint, *res = NULL;
    int                ret, domain;

    memset(&addr, 0, sizeof(addr));
    memset(&hint, 0, sizeof hint);
    addr.sin_port  = htons(port);
    hint.ai_family = AF_UNSPEC;
    hint.ai_flags  = AI_NUMERICHOST;

    ret = getaddrinfo(address, NULL, &hint, &res);

    if (ret) {
        err_msg = "invalid address";
        return -1;
    }
    if (res->ai_family == AF_INET) {
        domain = AF_INET;
        addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, address, &addr.sin_addr) != 1) {
            goto error;
        }
    } else if (res->ai_family == AF_INET6) {
        domain = AF_INET6;
        addr.sin_family = AF_INET6;
        if (inet_pton(AF_INET6, address, &addr.sin_addr) != 1) {
            goto error;
        }
    } else {
        error:
        err_msg = "invalid address";
        return -1;
    }

    freeaddrinfo(res);

    const int server = socket(domain, SOCK_STREAM, protocol);

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
    return server;
}


void metrics_init() {
    proxy_metrics.transferred_bytes      = 0;
    proxy_metrics.historic_accesses      = 0;
    proxy_metrics.concurrent_connections = 0;


}

void conf_init(char *media_types, char *transf_p, char *error_f) {
    proxy_configurations.media_types            = media_types;
    proxy_configurations.transformation_program = transf_p;
    proxy_configurations.error_file             = error_f;
    if (proxy_configurations.transformation_program != NULL) {
        proxy_configurations.transformation_on = 1;
    } else {
        proxy_configurations.transformation_on = 0;
    }
}