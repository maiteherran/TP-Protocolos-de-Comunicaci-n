#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <signal.h>
#include "Utils/buffer.h"
#include "Utils/stm.h"
#include "Parser/http_chunk_decoder.h"
#include "proxy5nio.h"
#include "proxy_reporter.h"
#include "Utils/log.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define BUFFER_SIZE 4096

//lista:
//Host: bar:9090
//cerrar bien en request y response
//logear
//metricas
//header accept
// escuchar las 2 bocas y poner un timer en el selector de 90s si nadie me mando nada cierro
// cat | gzip -d | cat

/** maquina de estados general */
enum proxy_v5state {
    /*
     * Recibe el request http del cliente, lo parsea hasta encontrar el host a donde debe conectarse
     *
     * Transiciones:
     * REQUESTA_RESOLV si encuentra el host
     * ERROR si no encuentra el host o algun caso de error
     *
     */
            REQUEST_READ,
    /*
     * Resolucion DNS del host
     *
     * Transiciones:
     * CONNECTING conexion propiamente dicha con el origin server
     * ERROR caso que no se haya podido realizar la resolucion dns o no se pueda conectar al host
     *
     */
            REQUEST_RESOLV,
    /*
     * Conexion propiamente dicha con el origin server
     *
     * Transiciones:
     * REQUEST_WRITE para enviar el request http del cliente al origin server
     * REQUEST_RESOLV si no nos pudimos conectar volvemos al estado REQUEST_RESOLV buscando pidiendo otra resolucion dns
     */
            CONNECTING,
    /*
     *
     *
     * Transiciones:
     */
            C_COMUNICATE,
    /*
     * Realiza la transforacion del body
     *
     * Transiciones:
     * DONE transformacion comletada y recivida por el cliente
     * ERROR caso que no se pudo realizar la transformacion o error en la comunicacion entre partes
     */
            TRANSFORM,
    /*
     * Como no hay nada que modificar en el body de la respuesta, se lo enviamos directo al cliente
     *
     * Transiciones:
     * DONE transformacion comletada y recivida por el cliente
     * ERROR caso que no se pudo realizar la transformacion o error en la comunicacion entre partes
     */
            COPY_BODY,
    /*
     * Proxy realizado, procedemos a cerrar las conneciones y liberar recursos
     *
     * Transiciones:
     * ninguna
     */
            DONE,
    /*
     * Si se presenta algun error terminamos en este estado, se cierran las conexiones y se liberan recursos
     *
     * Transiciones:
     * ninguna
     */
            ERROR
};

enum proxy_v5_origin_state {
    /*
     *
     *
     * Transiciones:
     */
            O_COMUNICATE,
    /*
     *
     *
     * Transiciones:
     */
            O_DONE,
    /*
     *
     *
     * Transiciones:
     */
            O_ERROR
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por REQUEST_READ, REQUEST_WRITE, REQUEST_RESOLV */

//struct t_request {
//    char              *method, *path, *host, *body;
//    int               version, body_len;
//    struct phr_header *headers;
//    size_t            num_headers;
//    size_t            bad_request;
//    size_t            port;
//};

struct request_st {
    /** buffer utilizado para I/O */
    buffer *rb, *wb;

    struct request        request;
    struct request_parser parser;

    // ¿a donde nos tenemos que conectar?
    struct sockaddr_storage *origin_addr;
    socklen_t               *origin_addr_len;
    int                     *origin_domain;

    int request_done;
    int header_close_added;

    const int *client_fd;
    int       *origin_fd;
};

enum response_state {
    RESPONSE_STATUS,
    RESPONSE_HEADERS,
    RESPONSE_BODY,
};

struct response_st {
    enum response_state state;
    int                 response_done;
    const int           *client_fd;
    int                 *origin_fd;
};

struct transform_st {
    buffer                     *t_wb, *t_rb;
    struct phr_chunked_decoder decoder;
    int                        t_writefd;
    int                        t_readfd;
    int                        transform_done;
    pid_t                      slavePid;
    const int                  *client_fd;
    int                        *origin_fd;
};

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct proxy5 {
    /** información del cliente */
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    int                     client_fd;

    /** resolución de la dirección del origin server */
    struct addrinfo *origin_resolution;
    /** intento actual de la dirección del origin server */
    struct addrinfo *origin_resolution_current;

    /** información del origin server */
    struct sockaddr_storage origin_addr;
    socklen_t               origin_addr_len;
    int                     origin_domain;
    int                     origin_fd;
    int                     origin_type;
    int                     origin_protocol;

    /** maquinas de estados */
    struct state_machine client_stm;
    struct state_machine origin_stm;

    struct request_st   request;
    struct transform_st transform;
    struct response_st  response;

    int transformation_on; // TODO: por ahora esta aca en una varible y me fijo en response si entro o no
    int chunked_set;

    /** buffers para ser usados read_buffer, write_buffer.*/
    uint8_t raw_buff_a[BUFFER_SIZE], raw_buff_b[BUFFER_SIZE];
    buffer  read_buffer, write_buffer;

    /** cantidad de referencias a este objeto. si es uno se debe destruir */
    unsigned references;

    /** siguiente en el pool */
    struct proxy5 *next;
};


/**
 * Pool de `struct proxy5', para ser reusados.
 *
 * Como tenemos un unico hilo que emite eventos no necesitamos barreras de
 * contención.
 */

static const unsigned max_pool  = 50; // tamaño máximo
static unsigned       pool_size = 0;  // tamaño actual
static struct proxy5  *pool     = 0;  // pool propiamente dicho

static const struct state_definition *
proxy5_client_describe_states(void);

static const struct state_definition *
proxy5_origin_describe_states(void);

/** crea un nuevo `struct proxy5' */
static struct proxy5 *
proxy5_new(int client_fd) {
    struct proxy5 *ret;

    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret  = pool;
        pool = pool->next;
        ret->next = 0;
    }
    if (ret == NULL) {
        goto finally;
    }
    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd       = -1;
    ret->client_fd       = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->client_stm.initial   = REQUEST_READ;
    ret->client_stm.max_state = ERROR;
    ret->client_stm.states    = proxy5_client_describe_states();
    stm_init(&ret->client_stm);

    ret->origin_stm.initial   = O_COMUNICATE;
    ret->origin_stm.max_state = O_ERROR;
    ret->origin_stm.states    = proxy5_origin_describe_states();
    stm_init(&ret->origin_stm);


    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);
    buffer_compact(&ret->read_buffer, 0);

    ret->transformation_on = 0;
    ret->chunked_set       = 0;

    ret->references = 1;
    finally:
    return ret;
}

/** realmente destruye */
static void
proxy5_destroy_(struct proxy5 *s) {
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct proxy5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
proxy5_destroy(struct proxy5 *s) {
    if (s == NULL) {
        // nada para hacer
    } else if (s->references == 1) {
        if (pool_size < max_pool) {
            s->next = pool;
            pool = s;
            pool_size++;
        } else {
            proxy5_destroy_(s);
        }
    } else {
        s->references -= 1;
    }
}

void
proxyv5_pool_destroy(void) {
    struct proxy5 *next, *s;
    for (s = pool; s != NULL; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (proxy5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct proxy5 *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void proxyv5_read(struct selector_key *key);

static void proxyv5_write(struct selector_key *key);

static void proxyv5_block(struct selector_key *key);

static void proxyv5_close(struct selector_key *key);

static const struct fd_handler proxy5_handler = {
        .handle_read   = proxyv5_read,
        .handle_write  = proxyv5_write,
        .handle_close  = proxyv5_close,
        .handle_block  = proxyv5_block,
};

/** Intenta aceptar la nueva conexión entrante*/
void
proxyv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len = sizeof(client_addr);
    struct proxy5           *state          = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
    if (client == -1) {
        log_debug("Accept Client Fail\n");
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        log_debug("setting client flags failed\n");
        goto fail;
    }
    state = proxy5_new(client);

    if (state == NULL) {
        log_debug("No hay estado\n");
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &proxy5_handler, OP_READ, state)) {
        log_debug("No se pudeo registrar el cliente en el selector\n");
        goto fail;
    }
    log_debug("Cliente conectado y registrado\n");
    return;
    fail:
    if (client != -1) {
        close(client);
    }
    proxy5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST_READ
////////////////////////////////////////////////////////////////////////////////
static void *
request_resolv_blocking(void *data);

/** inicializa las variables de los estados REQUEST_… */
static void
request_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->request;

    d->rb             = &(ATTACHMENT(key)->read_buffer);
    d->wb             = &(ATTACHMENT(key)->write_buffer);
    d->client_fd      = &ATTACHMENT(key)->client_fd;
    d->origin_fd      = &ATTACHMENT(key)->origin_fd;
    d->parser.request = &d->request;
    request_parser_init(&d->parser);
    d->origin_addr     = &ATTACHMENT(key)->origin_addr;
    d->origin_addr_len = &ATTACHMENT(key)->origin_addr_len;
    d->origin_domain   = &ATTACHMENT(key)->origin_domain;
    d->request_done    = 0;
}

static unsigned
request_process(struct selector_key *key, struct request_st *d);

/** lee todos los bytes del mensaje de tipo `request' y inicia su proceso */
static unsigned
request_read(struct selector_key *key) {
    struct request_st *d    = &ATTACHMENT(key)->request;

    buffer   *buff = d->rb;
    unsigned ret   = REQUEST_READ;
    bool              error = false;
    uint8_t  *ptr;
    size_t   count;
    ssize_t  n;
    int      st;

    if (!buffer_can_write(buff)) {
        /*
         * Si llegamos aca, el buffer esta lleno y no encontramos un host a cual conectarnos, por lo que aun no tenemos
         * donde vaciar el buffer. Enviamos un error 400 y retonamos con error cerrando la conexion
         */
        report(*d->client_fd, REPORT_400);
        return ERROR;
    }

    ptr = buffer_write_ptr(buff, &count);
    n   = read(key->fd, ptr, count);
    if (n > 0) {
        buffer_write_adv(buff, n);
        st = request_consume(buff, &d->parser, &error);
        if (request_is_done(st, &error)) {
            ret = request_process(key, d);
        }
    } else if (n == 0) {
        d->request_done = 1;
    } else {
        ret = ERROR;
    }
    return ret;
}

static unsigned
request_process(struct selector_key *key, struct request_st *d) {
    printf("%s", d->rb->read);
    pthread_t           tid;
    struct selector_key *k = malloc(sizeof(*key));
    memcpy(k, key, sizeof(*k));
    pthread_create(&tid, 0, request_resolv_blocking, k);
    selector_set_interest_key(key, OP_NOOP);
    return REQUEST_RESOLV;
}

////////////////////////////////////////////////////////////////////////////////
// RESOLVE
////////////////////////////////////////////////////////////////////////////////
static unsigned
request_connect(struct selector_key *key, struct request_st *d);

static unsigned
request_resolv_done(struct selector_key *key);

static void *
request_resolv_blocking(void *data) {
    struct selector_key *key = (struct selector_key *) data;
    struct proxy5       *s   = ATTACHMENT(key);
    struct request_st   *d   = &ATTACHMENT(key)->request;

    log_debug("host: %s, port: %i\n", d->request.host, (int) d->request.port);

    pthread_detach(pthread_self());
    s->origin_resolution = 0;

    char portToString[BUFFER_SIZE];
    sprintf(portToString, "%d", (int) d->request.port);

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
    struct request_st *d = &ATTACHMENT(key)->request;
    struct proxy5     *s = ATTACHMENT(key);

    unsigned int ret = ERROR;

    for (struct addrinfo *current = s->origin_resolution; current != NULL; current = current->ai_next) {
        s->origin_domain   = current->ai_family;
        s->origin_addr_len = current->ai_addrlen;
        s->origin_type     = current->ai_socktype;
        s->origin_protocol = current->ai_protocol;
        memcpy(&s->origin_addr,
               current->ai_addr,
               current->ai_addrlen);
        ret = request_connect(key, d);
        if (ret != ERROR) {
            return ret;
        }
    }
      report(key->fd, REPORT_503);
    freeaddrinfo(s->origin_resolution);
    s->origin_resolution = 0;
    return ret;
}

static unsigned
request_connect(struct selector_key *key, struct request_st *d) {
    bool          error = false;
    int           *fd   = d->origin_fd;
    struct proxy5 *s    = ATTACHMENT(key);
    *fd = socket(s->origin_domain, s->origin_type, s->origin_protocol);
    if (*fd == -1) {
        error = true;
        goto finally;
    }
    if (selector_fd_set_nio(*fd) == -1) {
        goto finally;
    }
    if (-1 == connect(*fd, (const struct sockaddr *) &s->origin_addr, s->origin_addr_len)) {
        if (errno == EINPROGRESS) {
            // es esperable,  tenemos que esperar a la conexión

            // dejamos de de pollear el socket del cliente
            selector_status st = selector_set_interest_key(key, OP_NOOP);
            if (SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }

            // esperamos la conexion en el nuevo socket
            // polleamos el socket del origin server
            st = selector_register(key->s, *fd, &proxy5_handler, OP_WRITE | OP_READ,
                                   key->data); // escritura del request
            if (SELECTOR_SUCCESS != st) {
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
        abort();
    }

    finally:
    if (error) {
        if (*fd != -1) {
            close(*fd);
            *fd = -1;
        }
        report(key->fd, REPORT_500);
        return ERROR;
    }
    selector_set_interest_key(key, OP_READ | OP_WRITE); // lectura del request
    return C_COMUNICATE;
//    return CONNECTING;
}


////////////////////////////////////////////////////////////////////////////////
// REQUEST CONNECT
////////////////////////////////////////////////////////////////////////////////

/** la conexión ha sido establecida (o falló)  */
static unsigned
connecting(struct selector_key *key) {
    int               error;
    socklen_t         len = sizeof(error);
    struct request_st *d  = &ATTACHMENT(key)->request;
    struct proxy5     *p  = ATTACHMENT(key);

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        p->origin_resolution = p->origin_resolution->ai_next;
        return REQUEST_RESOLV; // pasasmos a buscar otra resolucion dns
    } else {
        if (error == 0) {
            selector_set_interest(key->s, *d->client_fd,
                                  OP_READ); // habiamos dejado de pollear al cliente, como nos conectamos pedimos lectura para ver si quedaba algo para leer
            *d->origin_fd = key->fd;
            return C_COMUNICATE;//REQUEST_WRITE;
        } else { // la conexion no pude ser establecida, desregistramos el fd y cerramos
            if (p->origin_resolution->ai_next != NULL) {
                selector_unregister_fd(key->s, key->fd);
                close(key->fd);
                p->origin_resolution = p->origin_resolution->ai_next;
            } else {
                report(*d->client_fd, REPORT_500);
                return ERROR;
            }
            return request_resolv_done(key); // pasamos a buscar otra resolucion dsn
            //TODO: la puedo llamar o es mejor retornar el estado?
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//  O_COMUNICATE
////////////////////////////////////////////////////////////////////////////////

static void
origin_comunicate_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->request;
    buffer_compact(d->rb, 1);
    buffer_reset_read(d->rb);
    d->header_close_added = 0;
}

/* Lectura de la respuesta del origin server*/
static unsigned
origin_read(struct selector_key *key) {
    struct response_st *d        = &ATTACHMENT(key)->response;
    int                origin_fd = ATTACHMENT(key)->origin_fd;
    buffer             *buff     = &ATTACHMENT(key)->write_buffer;
    size_t             count;
    unsigned           ret       = O_COMUNICATE;

    if (!buffer_can_write(buff)) {
        return ret;
    }

    char    *write_ptr = (char *) buffer_write_ptr(buff, &count);
    ssize_t recv       = read(origin_fd, write_ptr, count);
    if (recv > 0) {
        buffer_write_adv(buff, recv);
    } else if (recv == 0) {
        /*
         * Seteamos "Conection: close" en el request al origin, seguramente el cierre su conexion al terminar de enviar
         * datos. En este punto el origin cerro la conexion es decir el request termino, prendo el flag asi cuando se
         * acaban los datos del buffer pasamos al estado DONE
         */
        d->response_done = 1;
//        selector_set_interest_key(key, OP_NOOP);
//        selector_set_interest(key->s, *d->client_fd, OP_WRITE);
    } else {
        log_error("Error en el origin server");
        ret = O_ERROR;
    }
    return ret;
}

/* Escribimos el request del cliente en el origin server, agegamos el header Connection: close para indicarle que la conexion no sea persistente*/
static unsigned
origin_write(struct selector_key *key) {
    struct request_st *d        = &ATTACHMENT(key)->request;
    unsigned          ret       = O_COMUNICATE;
    buffer            *buff     = &ATTACHMENT(key)->read_buffer; // este es el que usa el cliente para leer
    int               origin_fd = ATTACHMENT(key)->origin_fd;
    uint8_t           *ptr;
    size_t            count;
    ssize_t           n;
    size_t            size;
    char              *eol;

    if (!buffer_can_read(buff)) {
        if (d->request_done) {
            selector_set_interest_key(key, OP_READ);
        }
        return ret;
    }

    char *read_ptr = (char *) buffer_read_ptr(buff, &size);

    if (!d->header_close_added) {
        if ((eol = strstr(read_ptr, "\r\n")) != NULL) { // es la primera linea del request
            n = write(origin_fd, read_ptr, (size_t) (eol - read_ptr) + 2);
            if (n >= 0) {
                buffer_read_adv(buff, (eol - read_ptr) + 2);
            } else {
                log_error("Error en el origin server");
                ret = O_ERROR;
            }
            // agregamos el header connection close, ya que no soportamos conexiones persistentes
            char *conection_close_msg = "Connection: close\r\n";
            n = write(origin_fd, conection_close_msg, strlen(conection_close_msg));
            if (n <= 0) {
                log_error("Error en el origin server");
                ret = O_ERROR;
            }
            d->header_close_added = 1;
        }
        return ret;
    }

    n = write(origin_fd, read_ptr, size);
    if (n > 0) {
        buffer_read_adv(buff, n);
        //printf("%.*s", (int) size, read_ptr);
    } else if (n == 0) {
        log_debug("cerro escritura el origin");
    } else {
        log_error("Error en el origin server");
        ret = O_ERROR;
    }

    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// C_COMUNICATE
////////////////////////////////////////////////////////////////////////////////

static void
client_comunicate_init(const unsigned state, struct selector_key *key) {
    struct response_st *r = &ATTACHMENT(key)->response;
    struct request_st  *d = &ATTACHMENT(key)->request;
    r->client_fd = &ATTACHMENT(key)->client_fd;
    r->origin_fd = &ATTACHMENT(key)->origin_fd;
    r->state     = RESPONSE_STATUS;
//    buffer_compact(d->rb, 1);
//    buffer_reset_read(d->rb);
}

/*Lectura del request del cliente*/
static unsigned
client_read(struct selector_key *key) {
    struct request_st *d    = &ATTACHMENT(key)->request;
    buffer            *buff = &ATTACHMENT(key)->read_buffer;
    unsigned          ret   = C_COMUNICATE;
    bool              error = false;
    uint8_t           *ptr;
    size_t            count;
    ssize_t           n;
    int               st;

    if (!buffer_can_write(buff)) {
        return ret;
    }

    ptr = buffer_write_ptr(buff, &count);
    n   = read(key->fd, ptr, count);
    if (n > 0) {
        buffer_write_adv(buff, n);
    } else if (n == 0) {
        d->request_done = 1;
//        selector_set_interest_key(key, OP_WRITE);
    } else {
        log_error("Error en el cliente");
        ret = ERROR;
    }
    return ret;
}

/* Escribimos la respuesta del origin server en el cliente*/
static unsigned
client_write(struct selector_key *key) {
    int                trasformation_on = ATTACHMENT(key)->transformation_on;
    buffer             *rb              = &ATTACHMENT(key)->write_buffer; // este es el que usa el origin para escribir
    struct response_st *r               = &ATTACHMENT(key)->response;
    int                *chunked_set     = &ATTACHMENT(key)->chunked_set;
    char               *read_ptr;
    size_t             count;
    ssize_t            n;
    char               header[BUFFER_SIZE];
    char               value[BUFFER_SIZE];
    char               *eol;                // pointer to end of line
    unsigned           ret              = C_COMUNICATE;

    if (!buffer_can_read(rb)) {
        if (r->response_done) {
            ret = DONE;
        }
        return ret;
    }

    read_ptr = (char *) buffer_read_ptr(rb, &count);
    eol      = strstr(read_ptr, "\r\n"); // retorna la primera aparecion de la subcadena \r\n
    if (eol == NULL || ((eol - read_ptr) + 2) > count) { // no hay una linea completa recivida
        if (!buffer_can_write(rb)) { // si el buffer esta lleno y no hay una linea completa retornamos error
            //TODO: si ya envie algo no puedo reportar, mejor cerrar la conexion?
            // report(*r->client_fd, REPORT_507);
            log_error("Se lleno el buffer y no podemos leer una linea completa de la respuesta");
            ret = ERROR;
        }
        return ret;
    }

    *eol = '\0';// agrego para poder usar funciones de comparacion de strings, dsp lo modificamos de neuvo a \r

    switch (r->state) {
        case RESPONSE_STATUS:
            *eol = '\r';
            n = write(*r->client_fd, read_ptr, (size_t) (eol - read_ptr) + 2);
            if (n > 0) {
                buffer_read_adv(rb, (eol - read_ptr) + 2);
                r->state = RESPONSE_HEADERS;
            } else {
                log_error("Error en el cliente");
                ret = ERROR;
            }
            // agregamos el header connection close, ya que no soportamos conexiones persistentes
            char *conection_close_msg = "Connection: close\r\n";
            n = write(*r->client_fd, conection_close_msg, strlen(conection_close_msg));
            if (n < 0) {
                log_error("Error en el cliente");
                ret = ERROR;
            }
            break;
        case RESPONSE_HEADERS:
            if (sscanf(read_ptr, "%[^:/]: %s", header, value) == 2) {
                *eol = '\r';
                if (strcasecmp(header, "Connection") ==
                    0) {  // enonctramos un header, chequeamso si es de conexion, si lo es no lo enviamos, queremos que sea no persistente
                    buffer_read_adv(rb, (eol - read_ptr) + 2);
                } else if (trasformation_on && (strcasecmp(header, "Content-Length") ==
                                                0)) { // censuramos si esta la transforamcion activada
                    buffer_read_adv(rb, (eol - read_ptr) + 2);
                } else if (trasformation_on && (strcasecmp(header, "Transfer-Encoding") == 0)) {
                    if (strcasecmp(value, "chunked") == 0) {
                        *chunked_set = 1;
                        n = write(*r->client_fd, read_ptr, (eol - read_ptr) + 2);
                        if (n > 0) {
                            buffer_read_adv(rb, (eol - read_ptr) + 2);
                        } else {
                            log_error("Error en el cliente");
                            ret = ERROR;
                        }
                    } else { // censuramos si es distinto de chunked
                        buffer_read_adv(rb, (eol - read_ptr) + 2);
                    }
                } else {
                    n = write(*r->client_fd, read_ptr, (eol - read_ptr) + 2); // mando el header
                    if (n > 0) {
                        buffer_read_adv(rb, (eol - read_ptr) + 2);
                    } else {
                        log_error("Error en el cliente");
                        ret = ERROR;
                    }
                }
            } else if (eol == read_ptr) { // es una linea vacia, a partir de ahora lo que sigue es el body
                *eol = '\r';
                if (trasformation_on) {
                    buffer_read_adv(rb, 2);
                }
                r->state = RESPONSE_BODY;
                goto respone_body;
            }
            break;
        case RESPONSE_BODY:
        respone_body:
            if (trasformation_on) {
                if (!*chunked_set) {
                    char *trasfer_encoding_chunked_msg = "Transfer-Encoding: chunked\r\n";
                    n = write(*r->client_fd, trasfer_encoding_chunked_msg, strlen(trasfer_encoding_chunked_msg));
                    if (n < 0) {
                        log_error("Error en el cliente");
                        ret = ERROR;
                    }
                }
                ret = TRANSFORM;
            } else {
                ret = COPY_BODY;
            }
            break;
    }
    return ret;
}


////////////////////////////////////////////////////////////////////////////////
// COPY_BODY
////////////////////////////////////////////////////////////////////////////////

/*Lectura del request del cliente*/
static unsigned
http_read(struct selector_key *key) {
    struct request_st *d    = &ATTACHMENT(key)->request;
    buffer            *buff = &ATTACHMENT(key)->read_buffer;
    unsigned          ret   = COPY_BODY;
    bool              error = false;
    uint8_t           *ptr;
    size_t            count;
    ssize_t           n;
    int               st;

    if (!buffer_can_write(buff)) {
        return ret;
    }

    ptr = buffer_write_ptr(buff, &count);
    n   = read(key->fd, ptr, count);
    if (n > 0) {
        buffer_write_adv(buff, n);
    } else if (n == 0) {
        d->request_done = 1;
//        selector_set_interest_key(key, OP_WRITE);
    } else {
        log_error("Error en el cliente");
        ret = ERROR;
    }
    return ret;
}

static unsigned
http_body_write(struct selector_key *key) {
    buffer             *rb = &ATTACHMENT(key)->write_buffer;
    struct response_st *r  = &ATTACHMENT(key)->response;
    char               *read_ptr;
    size_t             count;
    ssize_t            n;
    unsigned           ret = COPY_BODY;

    if (!buffer_can_read(rb)) {
        if (r->response_done) {
            ret = DONE;
        }
        return ret;
    }

    read_ptr = (char *) buffer_read_ptr(rb, &count);
    n        = write(*r->client_fd, read_ptr, count);
    if (n > 0) {
        buffer_read_adv(rb, n);
    } else if (n == 0) {
        /* seria un error ya que no podemos escribir lo que queda de la respuesta en el buffer */
        log_debug("cerro escritura el cliente");
        ret = ERROR;
    } else {
        log_error("Error en el cliente");
        // nada que reportar, file descriptor esta roto
        ret = ERROR;
    }

    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// TRANSFORM
////////////////////////////////////////////////////////////////////////////////
static void
transf_write(struct selector_key *key);

static void
transf_read(struct selector_key *key);

static void
transf_close(struct selector_key *key);

static const struct fd_handler transformation_handler = {
        .handle_read   = transf_read,
        .handle_write  = transf_write,
        .handle_close  = transf_close,
        .handle_block  = NULL,
};


/*lemos el resultado de la transformacion y la guardamos en un buffer, luego seteamos interes de escritura en el fd del cliemte
 * donde guardadremos el contenido del buffer*/
static void
transf_read(struct selector_key *key) {
    struct transform_st *r    = &ATTACHMENT(key)->transform;
    buffer              *buff = r->t_wb; // en este buffer se guarda la salida
    size_t              count;
    uint8_t             *wrt_ptr;
    ssize_t             ret;

    if (!buffer_can_write(buff)) {
        return;
    }

    wrt_ptr = buffer_write_ptr(buff, &count);
    ret     = (size_t) read(r->t_readfd, wrt_ptr, count);
    if (ret < 0) {
        return;
        // cerramos la transformacion
    } else if (ret == 0) { // se cerro la escritura, la transformacion ya finalizo, procedemos a cerrrar la lectura
        r->transform_done = 1;
        /* dejamos de pollear el fd de lectura
         * no hay mas contenido que leer, cerramos la el fd de lectura
         */
        selector_set_interest(key->s, r->t_readfd, OP_NOOP);
        close(r->t_readfd);
        return;
    } else {
        buffer_write_adv(buff, ret);
    }
}

/*lemos el response body guardado en el buffer y se lo pasamos al programa */ // TODO : como pija mando el eof
static void
transf_write(struct selector_key *key) {
    struct transform_st *t    = &ATTACHMENT(key)->transform;
    struct response_st  *r    = &ATTACHMENT(key)->response;
    buffer              *buff = t->t_rb; // en este buffer leemos contendido del response body para pasarselo a nuestro programa transformador
    size_t              count;
    uint8_t             *read_ptr;
    ssize_t             ret;
    ssize_t             done  = 0;

    if (!buffer_can_read(buff)) {
        if (r->response_done) {
            /* dejamos de pollear el fd de lectura
             *no hay mas contenido que mandar, cerramos la el file descriptor de escritura
             */
            selector_set_interest(key->s, t->t_writefd, OP_NOOP);
            close(t->t_writefd);
        }
        return;
    }

    read_ptr = buffer_read_ptr(buff, &count);

    /*
     * hago un backup de la cantidad que podemos leer, el decoder borro chuncks y trailers del buffer por lo que su contenido solo
     * puede disminuir, no aumentar. Este back up sirve para no perder el puntero a write, por lo que una vez hecho el decode avanzamos la cantidad leida
     */
    size_t count_back_up = count;

    if (ATTACHMENT(key)->chunked_set) {
        done = decode_chunked(&t->decoder, (char *) read_ptr, &count);
        if (done == 1) {
            t->transform_done = 1;

            /* TODO: matamos al proceso esclavo ya que no queda nada por transfromar */

        }

    }
    ret = write(t->t_writefd, read_ptr, count);
    if (ret < 0) {
        return;
        // cerramos la transformacion
    } else {

        buffer_read_adv(buff,
                        count_back_up); // todo: estoy asumiendo que esto se envio todo, caso que no deberia encerrarlo en un while?, si entra de nuevo va querer decodificar lo que leyo mezclandome el estado del decodificador
    }
}

static void
transf_close(struct selector_key *key) {
    struct transform_st *r = &ATTACHMENT(key)->transform;
    //TODO:
}

static void
transform_init(const unsigned state, struct selector_key *key) {
    struct transform_st *r     = &ATTACHMENT(key)->transform;
    struct proxy5       *proxy = ATTACHMENT(key);
    r->client_fd                   = &ATTACHMENT(key)->client_fd;
    r->origin_fd                   = &ATTACHMENT(key)->origin_fd;
    r->t_rb                        = &ATTACHMENT(key)->write_buffer;
    r->t_wb                        = &ATTACHMENT(key)->read_buffer;
    r->decoder.state               = CHUNK_SIZE;
    r->decoder.hex_count           = 0;
    r->decoder.bytes_left_in_chunk = 0;
    r->transform_done              = 0;

    int infd[2];
    int outfd[2];

    pipe(infd);
    pipe(outfd);

    pid_t pid = fork();
    if (pid < 0) {
        report(*r->client_fd, REPORT_TRANSFORMATION_ERROR);
        // TODO: cerramos todo o que onda?
    }

    if (pid == 0) {
        // por las dudas hago un flush en todos
        fflush(stdin);
        fflush(stdout);
        fflush(stderr);
        dup2(infd[0], STDIN_FILENO); // lectura
        dup2(outfd[1], STDOUT_FILENO); // escritura
        close(infd[1]); // cierro escritura en in
        close(outfd[0]); // cierro lectura en out
        close(STDERR_FILENO);

        execl("/bin/sh", "sh", "-c", "cat > /tmp/foo && cat /tmp/foo", (char *) 0);
    } else {
        r->slavePid = pid;

        close(infd[0]); // cierrro lectura
        close(outfd[1]);  // cierro escritura
        r->t_readfd  = outfd[0];
        r->t_writefd = infd[1];

        selector_fd_set_nio(r->t_readfd);
        selector_fd_set_nio(r->t_writefd);

        if (SELECTOR_SUCCESS != selector_register(key->s, r->t_writefd, &transformation_handler, OP_WRITE, proxy)) {
            report(*r->client_fd, REPORT_TRANSFORMATION_ERROR);
            return;

            //TODO: llamao a la funcion proxy donde desde aca directo o medio villero?

        }
        if (SELECTOR_SUCCESS != selector_register(key->s, r->t_readfd, &transformation_handler, OP_READ, proxy)) {
            report(*r->client_fd, REPORT_TRANSFORMATION_ERROR);
            return;


            //TODO: llamao a la funcion proxy donde desde aca directo o medio villero?
        }
    }
}

static void
transform_close(const unsigned state, struct selector_key *key) {
    struct transform_st *t     = &ATTACHMENT(key)->transform;
    int                 status = kill(t->slavePid, SIGKILL);
    if (status < 0) {
        log_debug("No se pudo matar a proceso esclavo");
    } else {
        log_debug("Proceso esclavo muerto");
    }
}


/* Escribe el contenido transformado en el el cliente */
static unsigned
transform_write(struct selector_key *key) {
    struct transform_st *r    = &ATTACHMENT(key)->transform;
    buffer              *buff = r->t_wb;
    char                *read_ptr;
    size_t              count;
    ssize_t             n;

    if (!buffer_can_read(buff)) {
        if (r->transform_done) {
            return DONE;
        }
        return TRANSFORM;
    }
    read_ptr = (char *) buffer_read_ptr(buff, &count);
    dprintf(*r->client_fd, "\r\n%x\r\n",
            (int) count); // TODO: que hacemos si write no manda la cantidad que yo especifique aca?
    n = write(*r->client_fd, read_ptr, count);
    if (n > 0) {
        buffer_read_adv(buff, n);
    } else {
        report(*r->client_fd, REPORT_TRANSFORMATION_ERROR);
        return ERROR;
    }
    return TRANSFORM;
}


static unsigned //leemos del origin server y guardamos un el buffer
transform_read(struct selector_key *key) {
//    struct transform_st *r    = &ATTACHMENT(key)->transform;
//    buffer              *buff = r->t_rb;
//    size_t              count;
//    char                *write_ptr;
//
//    if (!buffer_can_write(buff)) {
//        return TRANSFORM;
//    }
//
//    write_ptr = (char *) buffer_write_ptr(buff, &count);
//    ssize_t ret = read(*r->origin_fd, write_ptr, count);
//    if (ret > 0) {
//        buffer_write_adv(buff, ret);
//    } else if (ret == 0) {
//        r->transform_done = 1;
//    } else {
////        report(*r->client_fd, REPORT_TRANSFORMATION_ERROR);
//        return ERROR;
//    }
//
    return TRANSFORM;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
        {
                .state            = REQUEST_READ,
                .on_arrival       = request_init,
                .on_read_ready    = request_read,
        },
        {
                .state            = REQUEST_RESOLV,
                .on_block_ready   = request_resolv_done,
        },
        {
                .state            = CONNECTING,
                .on_write_ready   = connecting,
        },
        {
                .state            = C_COMUNICATE,
                .on_arrival       = client_comunicate_init,
                .on_write_ready   = client_write,
                .on_read_ready    = client_read,
        },
        {
                .state            = TRANSFORM,
                .on_arrival       = transform_init,
                .on_read_ready    = transform_read,
                .on_write_ready   = transform_write,
                .on_departure     = transform_close,
        },
        {
                .state            = COPY_BODY,
                .on_read_ready    = client_read,
                .on_write_ready   = http_body_write,
                .on_read_ready    = http_read,

        },
        {
                .state            = DONE,

        },
        {
                .state            = ERROR,
        }
};

static const struct state_definition origin_statbl[] = {
        {
                .state            = O_COMUNICATE,
                .on_arrival       = origin_comunicate_init,
                .on_write_ready   = origin_write,
                .on_read_ready    = origin_read,
        },
        {
                .state                = O_DONE,

        },
        {
                .state                = O_ERROR,
        }
};

static const struct state_definition *
proxy5_origin_describe_states(void) {
    return origin_statbl;
}

static const struct state_definition *
proxy5_client_describe_states(void) {
    return client_statbl;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
proxyv5_done(struct selector_key *key);


struct state_machine *
getSmt(struct selector_key *key) {
    struct proxy5 *p = ATTACHMENT(key);
    if (key->fd == p->client_fd) {
        return &p->client_stm;
    } else {
        return &p->origin_stm;
    }
}

void
error_done_check(struct selector_key *key, const enum proxy_v5state st) {
    struct proxy5 *p = ATTACHMENT(key);
    if (key->fd == p->client_fd) {
        if (ERROR == st || DONE == st) {
            proxyv5_done(key);
        }
    } else {
        if (O_ERROR == st || O_DONE == st) {
            proxyv5_done(key);
        }
    }
}

static void
proxyv5_read(struct selector_key *key) {
    struct state_machine     *stm = getSmt(key);
    const enum proxy_v5state st   = stm_handler_read(stm, key);

    error_done_check(key, st);
}

static void
proxyv5_write(struct selector_key *key) {
    struct state_machine     *stm = getSmt(key);
    const enum proxy_v5state st   = stm_handler_write(stm, key);

    error_done_check(key, st);
}

static void
proxyv5_block(struct selector_key *key) {
    struct state_machine     *stm = getSmt(key);
    const enum proxy_v5state st   = stm_handler_block(stm, key);

    error_done_check(key, st);
}

static void
proxyv5_close(struct selector_key *key) {
    proxy5_destroy(ATTACHMENT(key));
}

static void
proxyv5_done(struct selector_key *key) {
    log_debug("CONEXION CERRADA");
    const int     fds[] = {
            ATTACHMENT(key)->client_fd,
            ATTACHMENT(key)->origin_fd,
    };
    for (unsigned i     = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}
