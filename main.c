//#include <netdb.h>
//#include "Parser/picohttpparser.h"
//#include "main.h"
//#define PORT 8080
//#define COLA 10
//#define BUFFER 1024
//
//int main(int argc, char *argv[]) {
//    setbuf(stdout, 0);
//    if (argc != 2) {
//        printf("Parameter: <Server Port>");
//        return 1;
//    }
//    server(atoi(argv[1]));
//    return 0;
//}
//
//int server(int port) {
//    int serverSocket;
//    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
//        perror("socket failed");
//        exit(EXIT_FAILURE);
//    }
//    struct sockaddr_in address;
//    memset(&address, 0, sizeof(address));
//    address.sin_family = AF_INET;
//    address.sin_addr.s_addr = htonl(INADDR_ANY);
//    address.sin_port = htons(port);
//    int addrlen = sizeof(address);
//
//    if (bind(serverSocket, (struct sockaddr *)&address, sizeof(address))<0) {
//        perror("bind failed");
//        exit(EXIT_FAILURE);
//    }
//    if (listen(serverSocket, COLA) < 0) {
//        perror("listen");
//        exit(EXIT_FAILURE);
//    }
//    while (1) {
//        int requestSocket = accept(serverSocket, (struct sockaddr *)&address, (socklen_t*)&addrlen);
//        printf("cliente conectado\n");
//        if (requestSocket < 0) {
//            perror("accept");
//            continue;
//        }
//
//        struct t_request request = handleClientRequest(requestSocket);
//
////        FILE* requestReadfp = fdopen(requestSocket, "r");
//        FILE* requestWritefp = fdopen(requestSocket, "w");
//
//        if (!request.bad_request) {
//            printf("t_request\n");
//            printf("method is %s\n", request.method);
//            printf("path is %s\n", request.path);
//            printf("the host is %s\n", request.host);
//            printf("the port is %i\n", (int)request.port);
//            printf("HTTP version is 1.%d\n", request.version);
//            printf("headers:\n");
//            for (int i = 0; i != request.num_headers; i++) {
//                printf("%.*s: %.*s\n", (int)request.headers[i].name_len, request.headers[i].name, (int)request.headers[i].value_len, request.headers[i].value);
//            }
//        } else {
//            printf("Bad Request\n");
//            continue;
//        }
//
//        int originServerSocket = client(request.host, request.port);
//        if (originServerSocket < 0) {
//            perror("accept");
//            continue;
//        }
//
//        FILE* originWrite = fdopen(originServerSocket, "w");
//        FILE* originRead = fdopen(originServerSocket, "r");
//
//        do_http_request(request, "HTTP/1.1", originWrite);
//        do_http_response(requestWritefp, originRead); // TODO: hacerlo no bloqueante
//
//        fclose(originWrite);
//        fclose(originRead);
////        fclose(requestReadfp);
//        fclose(requestWritefp);
//
//        close(originServerSocket);
//        close(requestSocket);
//
//        freeRequest(request);
//    }
//    return 0;
//}
//
//struct t_request handleClientRequest(int requestReadfp) {
//    char buffer[BUFFER] = {0};//"GET http://www.w3.org/pub/WWW/TheProject.html HTTP/1.1\r\n\r\n"; //"GET /pub/WWW/TheProject.html HTTP/1.1\r\nHost: www.w3.org\r\n\r\n";
//    struct t_request request;
//
//
//    //DESCOMENTAR si vas a usar netcat
//
//    FILE* requestRead = fdopen(requestReadfp, "r");
//    fread(buffer, sizeof(char), BUFFER, requestRead);
//
//    //    read(requestReadfp, buffer, BUFFER);
//
//    //DESCOMENTAR si vas a usar curl, configura para que los request vayan a tu proxy
//    /*
//    fd_set fds;
//    struct timeval timeout;
//    timeout.tv_sec = 1;
//    timeout.tv_usec = 0;
//    FD_ZERO(&fds);
//    FD_SET(requestReadfp, &fds);
//    ssize_t totalRead = 0;
//    ssize_t sizeRead  = 0;
//
//    if (select(requestReadfp + 1, &fds, NULL, NULL, &timeout) > 0) {  // espero contenido del request, voy leyendo hasta que se llene el buffer o me deja de mandar cosas, TODO: mejorar el metodo no bloqueante
//        sizeRead = read(requestReadfp, buffer + totalRead, BUFFER);
//        totalRead += sizeRead;
//        if (totalRead > BUFFER) {
//            request.bad_request = 1;
//            return request;
//        }
//    }
//     */
//    printf("%s\n", buffer);
//
//    char const *method, *path;
//    int pret, minor_version;
//    struct phr_header * headers = (struct phr_header *) calloc(50, sizeof(struct phr_header));
//    size_t method_len, path_len;
//    size_t num_headers = 50; //sizeof(headers) / sizeof(headers[0]);
//    pret = //phr_parse_headers(buffer, strlen(buffer)+1, headers, &num_headers,0);
//            phr_parse_request(buffer, strlen(buffer)+1, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);
//    if (pret < 0) {
//        printf("error, %i\n", pret);
//        request.bad_request = 1;
//        return request;
//    }
//
//    request.host = malloc(BUFFER);
//    request.headers = headers;
//    request.method = malloc(method_len);
//    strncpy(request.method, method, method_len);
//    request.path = malloc(path_len);
//    strncpy(request.path, path, path_len);
//    request.version = minor_version;
//    request.num_headers = num_headers;
//    request.bad_request = 0;
//
//    int iport;
//    unsigned short cport = 80;
//    char hostaux[BUFFER], pathaux[BUFFER];
//    if ( strncasecmp(request.path, "http://", 7 ) == 0) {
//        strncpy(request.path, "http", 4 );
//        if ( sscanf(request.path, "http://%[^:/]:%d%s", hostaux, &iport, pathaux ) == 3)
//            cport = (unsigned short) iport;
//        else if (sscanf(request.path, "http://%[^/]%s", hostaux, pathaux ) == 2) {
//        } else if (sscanf(request.path, "http://%[^:/]:%d", hostaux, &iport ) == 2) {
//            cport = (unsigned short) iport;
//            *pathaux = '/';
//            *(pathaux+1) = '\0';
//        } else if (sscanf(request.path, "http://%[^/]", hostaux ) == 1) {
//            cport = 80;
//            *pathaux = '/';
//            *(pathaux+1) = '\0';
//        } else {
//            printf("Bad request\n");
//        }
//        request.port = 80;//cport;
//        strcpy(request.path, pathaux);
//        strcpy(request.host, hostaux);
//    } else {
//        int found = 0;
//        for (int i = 0; i != request.num_headers; ++i) {
//            if (strncasecmp(request.headers[i].name, "Host", request.headers[i].name_len) == 0) {
//                stpncpy(request.host, request.headers[i].value, request.headers[i].value_len);
//                char * hostName = strtok(request.host, ":");
//                char * port = strtok(NULL, ":");
//                if (port) {
//                    request.port = (size_t)atoi(port);
//                    request.port = 80; //80 para mi nginx
//                } else {
//                    request.port = 80;
//                }
//                found = 1;
//            }
//        }
//        if (!found) {
//            request.bad_request = 1;
//        }
//    }
//    return  request;
//}
//
//int client(char* hostname, size_t port) {
//    printf("host: %s, port: %i\n", hostname, (int)port);
//    char portToString[BUFFER];
//    sprintf(portToString, "%d", (int)port);
//
//    struct addrinfo addrCriteria;
//    memset(&addrCriteria, 0, sizeof(addrCriteria));
//    addrCriteria.ai_family = AF_UNSPEC;
//    addrCriteria.ai_socktype = SOCK_STREAM;
//    addrCriteria.ai_protocol = IPPROTO_TCP;
//
//    struct addrinfo *addrList;
//    int dnsStatus = getaddrinfo(hostname, portToString, &addrCriteria, &addrList);
//    if (dnsStatus != 0) {
//        printf("Unknown host.\n");
//        return -1;
//    }
//
//    int clientSocket = socket(addrList->ai_family, addrList->ai_socktype, addrList->ai_protocol);
//    int connectStatus = connect(clientSocket, addrList->ai_addr, addrList->ai_addrlen);
//    freeaddrinfo(addrList);
//    if (connectStatus < 0) {
//        close(clientSocket);
//        printf("Service unavailable");
//        return -1;
//    }
//    return clientSocket;
//}
//
//void do_http_request(struct t_request request, char* protocol,  FILE* originWritefp) {
//    /* Send t_request. */
//    printf("pedi esto\n");
//    printf("%s %s %s\n", request.method, request.path, protocol);
//    printf("Host: %s\n", request.host);
//    fprintf(originWritefp, "%s %s %s\r\n", request.method, request.path, protocol);
//    fprintf(originWritefp, "Host: %s\r\n", request.host);
//    fflush(originWritefp);
//
//    //todo: no estoy agregando los headers del request, por algun motivo aca se borro el contenido de request.headers averiguar que onda
//    /*
//     for (int i = 0; i != request.num_headers; i++) {
//        if (strncasecmp(request.headers[i].name, "Host", request.headers[i].name_len) != 0) {
//            fprintf(originWritefp, "%.*s: %.*s\n", (int)request.headers[i].name_len, request.headers[i].name, (int)request.headers[i].value_len, request.headers[i].value);
//            printf("%.*s: %.*s\n", (int)request.headers[i].name_len, request.headers[i].name, (int)request.headers[i].value_len, request.headers[i].value);
//            fflush(originWritefp);
//        }
//    }
//    */
//
//    fprintf(originWritefp, "\r\n");
//    fflush(originWritefp);
//}
//
//void do_http_response(FILE* clientWritefp, FILE* originReadfp) {
//    size_t length;
//    char * line = fgetln(originReadfp, &length);
//    fprintf(clientWritefp, "%.*s", (int)length, line); // agregamos la primera linea con el http status asi luego podemos poner el header Connection: close
//    fputs("Connection: close\r\n", clientWritefp);
//    fflush(clientWritefp);
//    while ((line = fgetln(originReadfp, &length)) != (char*) 0 && length > 0) {
//        fprintf(clientWritefp, "%.*s", (int)length, line);
//        fflush(clientWritefp);
//    }
//    fflush(clientWritefp);
//}
//
//void trim(char * line) {
//    size_t l = strlen(line);
//    while ( line[l-1] == '\n' || line[l-1] == '\r' )
//        line[--l] = '\0';
//}
//
//void freeRequest(struct t_request request) {
//    free(request.headers);
//    free(request.path);
//    free(request.method);
//}


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
#include "Utils/proxy5nio.h"

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

int
main(const int argc, const char **argv) {
    unsigned port = atoi(argv[1]);

    // no tenemos nada que leer de stdin
    close(0);

    const char *err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", port);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));

    if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(server, 1) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    if (selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
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
    const struct fd_handler proxyv5 = {
            .handle_read       = proxyv5_passive_accept,
            .handle_write      = NULL,
            .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server, &proxyv5,
                           OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
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

    if (server >= 0) {
        close(server);
    }
    return ret;
}
