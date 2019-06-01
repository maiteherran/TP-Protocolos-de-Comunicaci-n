#include <netdb.h>
#include "Parser/picohttpparser.h"
#include "main.h"
#define PORT 8080
#define COLA 10
#define BUFFER 1024

int main(int argc, char *argv[]) {
    setbuf(stdout, 0);
    if (argc != 2) {
        printf("Parameter: <Server Port>");
        return 1;
    }
    server(atoi(argv[1]));
    return 0;
}

int server(int port) {
    int serverSocket;
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    int addrlen = sizeof(address);

    if (bind(serverSocket, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(serverSocket, COLA) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    while (1) {
        int requestSocket = accept(serverSocket, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        printf("cliente conectado\n");
        if (requestSocket < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        FILE* requestWritefp = fdopen(requestSocket, "w");
        FILE* requestReadfp = fdopen(requestSocket, "r");

        struct t_request request = handleClientRequest(requestReadfp);

        if (!request.bad_request) {
            printf("t_request\n");
            printf("method is %s\n", request.method);
            printf("path is %s\n", request.path);
            printf("the host is %s\n", request.host);
            printf("the port is %i\n", (int)request.port);
            printf("HTTP version is 1.%d\n", request.version);
            printf("headers:\n");
            for (int i = 0; i != request.num_headers; ++i) {
                printf("%.*s: %.*s\n", (int)request.headers[i].name_len, request.headers[i].name,
                       (int)request.headers[i].value_len, request.headers[i].value);
            }
        }

        int originServerSocket = client(request.host, request.port);
        if (originServerSocket < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        FILE* originWrite = fdopen(originServerSocket, "w");
        FILE* originRead = fdopen(originServerSocket, "r");

        do_http_request(request, "HTTP/1.1", originWrite);
        do_http_response(requestWritefp, originRead);

        fclose(originWrite);
        fclose(originRead);
        fclose(requestReadfp);
        fclose(requestWritefp);
        close(originServerSocket);
        close(requestSocket);

        freeRequest(request);
    }
    return 0;
}

struct t_request handleClientRequest(FILE* requestReadfp) {
    char buffer[BUFFER] = {0};//"GET http://www.w3.org/pub/WWW/TheProject.html HTTP/1.1\r\n\r\n"; //"GET /pub/WWW/TheProject.html HTTP/1.1\r\nHost: www.w3.org\r\n\r\n";
    struct t_request request;
    fread(buffer, sizeof(char), BUFFER, requestReadfp);
    printf("%s\n", buffer);
    char const *method, *path;
    int pret, minor_version;
    struct phr_header * headers = (struct phr_header *) calloc(50, sizeof(struct phr_header));
    size_t method_len, path_len;
    size_t num_headers = 50; //sizeof(headers) / sizeof(headers[0]);
    pret = //phr_parse_headers(buffer, strlen(buffer)+1, headers, &num_headers,0);
            phr_parse_request(buffer, strlen(buffer)+1, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);
    if (pret < 0) {
        printf("error, %i\n", pret);
        request.bad_request = 1;
        return request;
    }

    request.host = malloc(BUFFER);
    request.headers = headers;
    request.method = malloc(method_len);
    strncpy(request.method, method, method_len);
    request.path = malloc(path_len);
    strncpy(request.path, path, path_len);
    request.version = minor_version;
    request.num_headers = num_headers;
    request.bad_request = 0;

    int iport;
    unsigned short cport = 80;
    char hostaux[BUFFER], pathaux[BUFFER];
    if ( strncasecmp(request.path, "http://", 7 ) == 0) {
        (void) strncpy(request.path, "http", 4 );
        if ( sscanf(request.path, "http://%[^:/]:%d%s", hostaux, &iport, pathaux ) == 3)
            cport = (unsigned short) iport;
        else if (sscanf(request.path, "http://%[^/]%s", hostaux, pathaux ) == 2) {
        } else if (sscanf(request.path, "http://%[^:/]:%d", hostaux, &iport ) == 2) {
            cport = (unsigned short) iport;
            *pathaux = '/';
            *(pathaux+1) = '\0';
        } else if (sscanf(request.path, "http://%[^/]", hostaux ) == 1) {
            cport = 80;
            *pathaux = '/';
            *(pathaux+1) = '\0';
        } else {
            printf("Bad request\n");
        }
        request.port = cport;
        strcpy(request.path, pathaux);
        strcpy(request.host, hostaux);
    } else {
        int found = 0;
        for (int i = 0; i != request.num_headers; ++i) {
            if (strcasecmp(request.headers[i].name, "Host") == 0) {
                stpncpy(request.host, request.headers[i].value, request.headers[i].value_len);
                found = 1;
            }
        }
        if (!found) {
            request.bad_request = 1;
        }
        request.port = 80;
    }
    return  request;
}

int client(char* hostname, size_t port) {
    printf("host: %s, port: %i\n", hostname, (int)port);
    char portToString[BUFFER];
    sprintf(portToString, "%d", (int)port);

    struct addrinfo addrCriteria;
    memset(&addrCriteria, 0, sizeof(addrCriteria));
    addrCriteria.ai_family = AF_UNSPEC;
    addrCriteria.ai_socktype = SOCK_STREAM;
    addrCriteria.ai_protocol = IPPROTO_TCP;

    struct addrinfo *addrList;
    int dnsStatus = getaddrinfo(hostname, portToString, &addrCriteria, &addrList);
    if (dnsStatus != 0) {
        printf("Unknown host.\n");
        return -1;
    }

    int clientSocket = socket(addrList->ai_family, addrList->ai_socktype, addrList->ai_protocol);
    int connectStatus = connect(clientSocket, addrList->ai_addr, addrList->ai_addrlen);
    freeaddrinfo(addrList);
    if (connectStatus < 0) {
        close(clientSocket);
        printf("Service unavailable");
        return -1;
    }
    return clientSocket;
}

void do_http_request(struct t_request request, char* protocol,  FILE* originWritefp) {
    /* Send t_request. */
    printf("pedi esto\n");
    printf("%s %s %s\n", request.method, request.path, protocol);
    printf("Host: %s\n", request.host);
    (void) fprintf(originWritefp, "%s %s %s\r\n", request.method, request.path, protocol);
    (void) fprintf(originWritefp, "Host: %s\r\n", request.host);
//    (void) fputs( "Connection: close\r\n", );
    (void) fflush(originWritefp);
    for (int i = 0; i != request.num_headers; ++i) {
        if (strcasecmp(request.headers[i].name, "Host") == 0) {
            printf("%.*s: %.*s\n", (int)request.headers[i].name_len, request.headers[i].name, (int)request.headers[i].value_len, request.headers[i].value);
            fprintf(originWritefp,"%.*s: %.*s\r\n", (int)request.headers[i].name_len, request.headers[i].name, (int)request.headers[i].value_len, request.headers[i].value);
            (void) fflush(originWritefp);
        }
    }
    fprintf(originWritefp, "\r\n");
    (void) fflush(originWritefp);
}

void do_http_response(FILE* clientWritefp, FILE* originReadfp) {
    size_t length;
    char * line = fgetln(originReadfp, &length);
    (void) fprintf(clientWritefp, "%.*s", (int)length, line); // agregamos la primera linea con el http status asi luego podemos poner el header Connection: close
    (void) fputs("Connection: close\r\n", clientWritefp);
    (void) fflush(clientWritefp);
    while ((line = fgetln(originReadfp, &length)) != (char*) 0 && length > 0) {
        (void) fprintf(clientWritefp, "%.*s", (int)length, line);
        (void) fflush(clientWritefp);
    }
    (void) fflush(clientWritefp);
}

void trim(char * line) {
    size_t l = strlen(line);
    while ( line[l-1] == '\n' || line[l-1] == '\r' )
        line[--l] = '\0';
}

void freeRequest(struct t_request request) {
    free(request.headers);
    free(request.path);
    free(request.method);
}
