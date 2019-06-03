/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include<stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>

#include <arpa/inet.h>

#include "hello.h"
#include "request.h"
#include "buffer.h"

#include "stm.h"
#include "socks5nio.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define BUFFER_SIZE 2048


/** maquina de estados general */
enum socks_v5state {
    REQUEST_READ,

    /**
     * Espera la resolución DNS
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd. Espera un evento de que la tarea bloqueante
     *               terminó.
     * Transiciones:
     *     - REQUEST_CONNECTING si se logra resolución al nombre y se puede
     *                          iniciar la conexión al origin server.
     *     - REQUEST_WRITE      en otro caso
     */
    REQUEST_RESOLV,

    /**
     * Espera que se establezca la conexión al origin server
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - REQUEST_WRITE    se haya logrado o no establecer la conexión.
     *
     */
//    REQUEST_CONNECTING,

    /**
     * envía la respuesta del `request' al cliente.
     *
     * Intereses:
     *   - OP_WRITE sobre client_fd
     *   - OP_NOOP  sobre origin_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - COPY         si el request fue exitoso y tenemos que copiar el
     *                  contenido de los descriptores
     *   - ERROR        ante I/O error
     */
    REQUEST_WRITE,
    /**
     * Copia bytes entre client_fd y origin_fd.
     *
     * Intereses: (tanto para client_fd y origin_fd)
     *   - OP_READ  si hay espacio para escribir en el buffer de lectura
     *   - OP_WRITE si hay bytes para leer en el buffer de escritura
     *
     * Transicion:
     *   - DONE     cuando no queda nada mas por copiar.
     */
//    COPY,

    // estados terminales
    DONE,
    ERROR,
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por REQUEST_READ, REQUEST_WRITE, REQUEST_RESOLV */

struct t_request {
    char *method, *path, *host;
    int version;
    struct phr_header * headers;
    size_t num_headers;
    size_t bad_request;
    size_t port;
};

struct request_st {
    /** buffer utilizado para I/O */
    buffer                    *rb, *wb;

    struct t_request request;

    // ¿a donde nos tenemos que conectar?
    struct sockaddr_storage   *origin_addr;
    socklen_t                 *origin_addr_len;
    int                       *origin_domain;

    const int                 *client_fd;
    int                       *origin_fd;
};

/** usado por REQUEST_CONNECTING */
struct connecting {
    buffer     *wb;
    const int  *client_fd;
    int        *origin_fd;
    enum socks_response_status *status;
};


/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
    /** información del cliente */
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    /** resolución de la dirección del origin server */
    struct addrinfo              *origin_resolution;
    /** intento actual de la dirección del origin server */
    struct addrinfo              *origin_resolution_current;

    /** información del origin server */
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_domain;
    int                           origin_fd;
    int                           origin_type;
    int                           origin_protocol;

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct request_st         request;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
    } orig;

    /** buffers para ser usados read_buffer, write_buffer.*/
    uint8_t raw_buff_a[BUFFER_SIZE], raw_buff_b[BUFFER_SIZE];
    buffer read_buffer, write_buffer;
    
    /** cantidad de referencias a este objeto. si es uno se debe destruir */
    unsigned references;

    /** siguiente en el pool */
    struct socks5 *next;
};


/**
 * Pool de `struct socks5', para ser reusados.
 *
 * Como tenemos un unico hilo que emite eventos no necesitamos barreras de
 * contención.
 */

static const unsigned  max_pool  = 50; // tamaño máximo
static unsigned        pool_size = 0;  // tamaño actual
static struct socks5 * pool      = 0;  // pool propiamente dicho

static const struct state_definition *
socks5_describe_states(void);

/** crea un nuevo `struct socks5' */
static struct socks5 *
socks5_new(int client_fd) {
    struct socks5 *ret;

    if(pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret       = pool;
        pool      = pool->next;
        ret->next = 0;
    }
    if(ret == NULL) {
        goto finally;
    }
    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd       = -1;
    ret->client_fd       = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm    .initial   = REQUEST_READ;
    ret->stm    .max_state = ERROR;
    ret->stm    .states    = socks5_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer,  N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->references = 1;
finally:
    return ret;
}

/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

/** Intenta aceptar la nueva conexión entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5                *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr, &client_addr_len);
    if(client == -1) {
        printf("Accept Client Fail\n");
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        printf("setting client flags failed\n");
        goto fail;
    }
    state = socks5_new(client);

    if(state == NULL) {
        printf("No hay estado\n");
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler, OP_READ, state)) {
        printf("No se pudeo registrar el cliente en el selector\n");
        goto fail;
    }
    printf("Cliente conectado y registrado\n");
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST
////////////////////////////////////////////////////////////////////////////////
static void *
request_resolv_blocking(void * data);

/** inicializa las variables de los estados REQUEST_… */
static void
request_init(const unsigned state, struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

    d->rb              = &(ATTACHMENT(key)->read_buffer);
    d->wb              = &(ATTACHMENT(key)->write_buffer);
    d->client_fd       = &ATTACHMENT(key)->client_fd;
    d->origin_fd       = &ATTACHMENT(key)->origin_fd;

    d->origin_addr     = &ATTACHMENT(key)->origin_addr;
    d->origin_addr_len = &ATTACHMENT(key)->origin_addr_len;
    d->origin_domain   = &ATTACHMENT(key)->origin_domain;
}

static unsigned
request_process(struct selector_key* key, struct request_st* d);

/** lee todos los bytes del mensaje de tipo `request' y inicia su proceso */
static unsigned
request_read(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

      buffer *b     = d->rb;
    unsigned  ret   = REQUEST_READ;
        bool  error = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(b, &count);
    n = recv(key->fd, ptr, count, 0); // leo el request recivido en el proxy server TODO: tendria que ser en un while no?
    if(n > 0) {
        buffer_write_adv(b, n);
    } else if (n == 0) {  // se leyo EOF

        return request_process(key, d);

    } else {
        ret = ERROR;
    }
    return ret;
}

static unsigned
request_process(struct selector_key* key, struct request_st* d) {
    size_t to_read;
    char * buffer = (char *)buffer_read_ptr(d->rb, &to_read);
    printf("%s", buffer);

    char const *method, *path;
    int pret, minor_version;
    struct phr_header * headers = (struct phr_header *) calloc(50, sizeof(struct phr_header));
    size_t method_len, path_len;
    size_t num_headers = 50; //sizeof(headers) / sizeof(headers[0]);
    pret = //phr_parse_headers(buffer, strlen(buffer)+1, headers, &num_headers,0);
            phr_parse_request(buffer, to_read, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);
    if (pret < 0) {
        printf("error, %i\n", pret);
        d->request.bad_request = 1;
        return ERROR;
    }

    d->request.host = malloc(BUFFER_SIZE);
    d->request.headers = headers;
    d->request.method = malloc(method_len);
    strncpy(d->request.method, method, method_len);
    d->request.path = malloc(path_len);
    strncpy(d->request.path, path, path_len);
    d->request.version = minor_version;
    d->request.num_headers = num_headers;
    d->request.bad_request = 0;

    int iport;
    unsigned short cport = 80;
    char hostaux[BUFFER_SIZE], pathaux[BUFFER_SIZE];
    if ( strncasecmp(d->request.path, "http://", 7 ) == 0) {
        strncpy(d->request.path, "http", 4 );
        if ( sscanf(d->request.path, "http://%[^:/]:%d%s", hostaux, &iport, pathaux ) == 3)
            cport = (unsigned short) iport;
        else if (sscanf(d->request.path, "http://%[^/]%s", hostaux, pathaux ) == 2) {
        } else if (sscanf(d->request.path, "http://%[^:/]:%d", hostaux, &iport ) == 2) {
            cport = (unsigned short) iport;
            *pathaux = '/';
            *(pathaux+1) = '\0';
        } else if (sscanf(d->request.path, "http://%[^/]", hostaux ) == 1) {
            cport = 80;
            *pathaux = '/';
            *(pathaux+1) = '\0';
        } else {
            d->request.bad_request = 1;
            printf("Bad request\n");
            return ERROR;
        }
        d->request.port = 80;//cport;
        strcpy(d->request.path, pathaux);
        strcpy(d->request.host, hostaux);
    } else {
        int found = 0;
        for (int i = 0; i != d->request.num_headers; ++i) {
            if (strncasecmp(d->request.headers[i].name, "Host", d->request.headers[i].name_len) == 0) {
                stpncpy(d->request.host, d->request.headers[i].value, d->request.headers[i].value_len);
                char * hostName = strtok(d->request.host, ":");
                char * port = strtok(NULL, ":");
                if (port) {
                    d->request.port = (size_t)atoi(port);
                    d->request.port = 80; //TODO: 80 para mi nginx
                } else {
                    d->request.port = 80;
                }
                found = 1;
            }
        }
        if (!found) {
            d->request.bad_request = 1;
            return ERROR;
        }
    }
    pthread_t tid;
    struct selector_key* k = malloc(sizeof(*key));
    memcpy(k, key, sizeof(*k));
    pthread_create(&tid, 0, request_resolv_blocking, k);
    selector_set_interest_key(key, OP_NOOP);
    return  REQUEST_RESOLV;
}


////////////////////////////////////////////////////////////////////////////////
// RESOLVE
////////////////////////////////////////////////////////////////////////////////
static unsigned
request_connect(struct selector_key *key, struct request_st *d);
static unsigned
request_resolv_done(struct selector_key *key);

static void *
request_resolv_blocking(void * data) {
    struct selector_key *key = (struct selector_key *) data;
    struct socks5       *s   = ATTACHMENT(key);
    struct request_st   *d   = &ATTACHMENT(key)->client.request;

    printf("host: %s, port: %i\n", d->request.host, (int)d->request.port);

    pthread_detach(pthread_self());
    s->origin_resolution = 0;

    char portToString[BUFFER_SIZE];
    sprintf(portToString, "%d", (int)d->request.port);

    struct addrinfo addrCriteria;
    memset(&addrCriteria, 0, sizeof(addrCriteria));
    addrCriteria.ai_family   = AF_UNSPEC;
    addrCriteria.ai_socktype = SOCK_STREAM;
    addrCriteria.ai_protocol = IPPROTO_TCP;

    getaddrinfo(d->request.host, portToString, &addrCriteria, &s->origin_resolution);

    selector_notify_block(key->s, key->fd);

    free(data);

    return 0;
}

static unsigned
request_resolv_done(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;
    struct socks5 *s      =  ATTACHMENT(key);

    s->origin_domain   = s->origin_resolution->ai_family;
    s->origin_addr_len = s->origin_resolution->ai_addrlen;
    s->origin_type     = s->origin_resolution->ai_socktype;
    s->origin_protocol = s->origin_resolution->ai_protocol;
    memcpy(&s->origin_addr,
            s->origin_resolution->ai_addr,
            s->origin_resolution->ai_addrlen);
    freeaddrinfo(s->origin_resolution);
    s->origin_resolution = 0;

    return request_connect(key, d);
}

static unsigned
request_connect(struct selector_key *key, struct request_st *d) {
    bool error                  = false;
    int *fd                     =  d->origin_fd;
    struct socks5 *s            =  ATTACHMENT(key);

    *fd = socket(s->origin_domain, s->origin_type, s->origin_protocol);
    if (*fd == -1) {
        error = true;
        goto finally;
    }
    if (selector_fd_set_nio(*fd) == -1) {
        goto finally;
    }
    if (-1 == connect(*fd, (const struct sockaddr *)&s->origin_addr, s->origin_addr_len)) {
        if(errno == EINPROGRESS) {
            // es esperable,  tenemos que esperar a la conexión

            // dejamos de de pollear el socket del cliente
            selector_status st = selector_set_interest_key(key, OP_NOOP);
            if(SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }

            // esperamos la conexion en el nuevo socket
            st = selector_register(key->s, *fd, &socks5_handler,
                                   OP_WRITE, key->data);
            if(SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }
            ATTACHMENT(key)->references += 1;
        } else {
            error = true;
            goto finally;
        }
    } else {
        // estamos conectados sin esperar... no parece posible
        // saltaríamos directamente a COPY
        abort(); //TODO: nose que hce esto
    }

    finally:
    if (error) {
        if (*fd != -1) {
            close(*fd);
            *fd = -1;
        }
        return ERROR; // TODO: lo puse yo, no majeamos status hasta ahora
    }

    return REQUEST_WRITE;
}

void do_http_request(struct t_request request, char* protocol,  FILE* originWritefp) {
    /* Send t_request. */
    printf("pedi esto\n");
    printf("%s %s %s\n", request.method, request.path, protocol);
    printf("Host: %s\n", request.host);
    fprintf(originWritefp, "%s %s %s\r\n", request.method, request.path, protocol);
    fprintf(originWritefp, "Host: %s\r\n", request.host);
    fflush(originWritefp);

    //todo: no estoy agregando los headers del request, por algun motivo aca se borro el contenido de request.headers averiguar que onda
    /*
     for (int i = 0; i != request.num_headers; i++) {
        if (strncasecmp(request.headers[i].name, "Host", request.headers[i].name_len) != 0) {
            fprintf(originWritefp, "%.*s: %.*s\n", (int)request.headers[i].name_len, request.headers[i].name, (int)request.headers[i].value_len, request.headers[i].value);
            printf("%.*s: %.*s\n", (int)request.headers[i].name_len, request.headers[i].name, (int)request.headers[i].value_len, request.headers[i].value);
            fflush(originWritefp);
        }
    }
    */

    fprintf(originWritefp, "\r\n");
    fflush(originWritefp);
}

void do_http_response(FILE* clientWritefp, FILE* originReadfp) {
    size_t length;
    char * line = fgetln(originReadfp, &length);
    fprintf(clientWritefp, "%.*s", (int)length, line); // agregamos la primera linea con el http status asi luego podemos poner el header Connection: close
    fputs("Connection: close\r\n", clientWritefp);
    fflush(clientWritefp);
    while ((line = fgetln(originReadfp, &length)) != (char*) 0 && length > 0) {
        fprintf(clientWritefp, "%.*s", (int)length, line);
        fflush(clientWritefp);
    }
    fflush(clientWritefp);
}


static unsigned
request_write(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

    unsigned  ret       = REQUEST_WRITE;
      buffer *b         = d->wb;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;


    FILE* originWrite = fdopen(ATTACHMENT(key)->origin_fd, "w");
    FILE* originRead = fdopen(ATTACHMENT(key)->origin_fd, "r");
    FILE* requestWritefp = fdopen(ATTACHMENT(key)->client_fd, "w");

    do_http_request(d->request, "HTTP/1.1", originWrite);
    do_http_response(requestWritefp, originRead); // TODO: hacerlo no bloqueante


    fclose(originWrite);
    fclose(originRead);
    fclose(requestWritefp);

    return ret;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = REQUEST_READ,
        .on_arrival       = request_init,
        .on_read_ready    = request_read,
    },{
        .state            = REQUEST_RESOLV,
        .on_block_ready   = request_resolv_done,
    }, {
        .state            = REQUEST_WRITE,
        .on_write_ready   = request_write,
    }, {
        .state            = DONE,

    },{
        .state            = ERROR,
    }
};

static const struct state_definition *
socks5_describe_states(void) {
    return client_statbl;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
socksv5_done(struct selector_key* key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}
