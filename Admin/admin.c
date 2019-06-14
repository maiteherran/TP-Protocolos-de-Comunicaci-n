/**
 * admin.c  - TODO: descripcion
 */
#include "admin.h"
#include<stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>
#include <arpa/inet.h>
#include "../Utils/buffer.h"
#include "../Utils/stm.h"
#include "HpcpParser/hpcpRequest.h"
#include "../Utils/log.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define MSG_NOSIGNAL       0x4000

#define CMD_HELLO_NARGS 0X01
#define CMD_AUTH_NARGS 0X02
#define CMD_CLOSE_NARGS 0X00
#define CMD_GET_MIN_NARGS 0X01
#define CMD_SET_MIN_NARGS 0X01
#define VERSION_SIZE 0x02


#define CONFIGURATIONS 0x00
#define METRICS 0x01
#define TRANSFORMATION_PROGRAM 0x01
#define TRANSFORMATION_PROGRAM_STATUS 0x02
#define MEDIA_TYPES 0x04
#define CONCURRENT_CONNECTIONS 0x01
#define HISTORIC_ACCESSES 0x02
#define TRANSFERRED_BYTES 0X04

/** maquina de estados general */
enum socks_v5state {

    HELLO_READ,

    HELLO_WRITE,

    AUTH_READ,

    AUTH_WRITE,

    COMAND_READ,

    COMAND_WRITE,

    REQUEST_ERROR,

    ERROR,
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

struct request_st {
    /** buffer utilizado para I/O */
    buffer *rb, *wb;

    /** parser */
    struct hpcp_request_parser *hpcp_parser;

    /*Request que está siendo parseado*/
    struct hpcp_request request;
    enum hpcp_response_status;

    const int *client_fd;
};


/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct hpcp {
    /** información del cliente */
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    int                     client_fd;

    char *username;

    struct request_st request;

    struct hpcp_request_parser hpcp_parser;

    /** maquinas de estados */
    struct state_machine stm;

    enum socks_v5state state_before_error;

    /** buffers para ser usados read_buffer, write_buffer.*/
    uint8_t raw_buff_a[2048], raw_buff_b[2048];
    buffer  read_buffer, write_buffer;

    /** cantidad de referencias a este objeto. si es uno se debe destruir */
    unsigned references;

    /** siguiente en el pool */
    struct hpcp *next;
};


/**
 * Pool de `struct hpcp', para ser reusados.
 *
 * Como tenemos un unico hilo que emite eventos no necesitamos barreras de
 * contención.
 */

static const unsigned max_pool  = 50; // tamaño máximo
static unsigned       pool_size = 0;  // tamaño actual
static struct hpcp    *pool     = 0;  // pool propiamente dicho

static const struct state_definition *
socks5_describe_states(void);

/** crea un nuevo `struct socks5' */
static struct hpcp *
socks5_new(int client_fd) {
    struct hpcp *ret;

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

    ret->client_fd       = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm.initial   = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states    = socks5_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    //ret->hpcp_parser.request = malloc(sizeof(struct hpcp_request));

    ret->request.client_fd   = &ret->client_fd;
    ret->hpcp_parser.request = &ret->request.request;
    ret->request.hpcp_parser = &ret->hpcp_parser;
    ret->request.rb          = &ret->read_buffer;
    ret->request.wb          = &ret->write_buffer;

    ret->references = 1;
    finally:
    return ret;
}

/** realmente destruye */
static void
socks5_destroy_(struct hpcp *s) {
    free_hpcp_request(&s->request.request);
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct hpcp *s) {
    if (s == NULL) {
        // nada para hacer
    } else if (s->references == 1) {
        if (s != NULL) {
            if (pool_size < max_pool) {
                s->next = pool;
                pool = s;
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
    struct hpcp *next, *s;
    for (s = pool; s != NULL; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct hpcp *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read(struct selector_key *key);

static void socksv5_write(struct selector_key *key);

static void socksv5_block(struct selector_key *key);

static void socksv5_close(struct selector_key *key);

static const struct fd_handler socks5_handler = {
        .handle_read   = socksv5_read,
        .handle_write  = socksv5_write,
        .handle_close  = socksv5_close,
        .handle_block  = socksv5_block,
};

/** Intenta aceptar la nueva conexión entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len = sizeof(client_addr);
    struct hpcp             *state          = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr,
                              &client_addr_len);
    if (client == -1) {
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if (state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    printf("Cliente admin conecntado");
    return;
    fail:
    if (client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

static void
on_read_departure(const unsigned state, struct selector_key *key) {
    struct request_st *r = &ATTACHMENT(key)->request;
//    free_hpcp_request(r->request);
}

////////////////////////////////////////////////////////////////////////////////
// HELLO_READ
////////////////////////////////////////////////////////////////////////////////

static unsigned
hello_process(struct selector_key *key, struct request_st *r);

/** inicializa las variables de los estados HELLO_… */
static void
hello_read_init(const unsigned state, struct selector_key *key) {
    struct request_st *r = &ATTACHMENT(key)->request;
    r->hpcp_parser->state   = hpcp_request_cmd;
}

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned
hello_read(struct selector_key *key) {
    struct request_st       *r    = &ATTACHMENT(key)->request;
    unsigned                ret   = HELLO_READ;
    bool                    error = false;
    struct buffer           *buff = r->rb;
    enum hpcp_request_state st;
    uint8_t                 *ptr;
    size_t                  count;
    ssize_t                 n;

    if (!buffer_can_write(buff)) {
        return ERROR;
    }

    ptr = buffer_write_ptr(buff, &count);
    n   = read(*r->client_fd, ptr, count);
    if (n > 0) {
        buffer_write_adv(buff, n);
        st = hpcp_request_consume(buff, r->hpcp_parser, &error);
        if (hpcp_request_is_done(st, &error)) {
            ret = hello_process(key, r);
        }
    } else {
        ret = ERROR;
    }
    return ret;
}

/** procesamiento del mensaje `hello' */
static unsigned
hello_process(struct selector_key *key, struct request_st *r) { // recivo error y proceso la respuesta
    struct buffer *buff = r->wb;
    struct hpcp_request *request = &r->request;
    if (request->nargs != CMD_HELLO_NARGS || request->args_sizes[0] != VERSION_SIZE) {
        printf("invalid hello args\n");
        return ERROR;
    }
//    if (request->args[0][0] != 0x01 || request->args[0][1] != 0x00) {
//        printf("invalid version\n");
//        return ERROR;
//    }
    buffer_write(buff, hpcp_status_ok);
    buffer_write(buff, 0x00);
    selector_set_interest_key(key, OP_WRITE);
    return HELLO_WRITE;
}

////////////////////////////////////////////////////////////////////////////////
// HELLO_WRITE
////////////////////////////////////////////////////////////////////////////////

/** escribe todos los bytes de la respuesta al mensaje `hello' */
static unsigned
hello_write(struct selector_key *key) {
    int           client_fd = ATTACHMENT(key)->client_fd;
    struct buffer *buff     = &ATTACHMENT(key)->write_buffer;
    unsigned      ret       = AUTH_READ;
    uint8_t       *ptr;
    size_t        count;
    ssize_t       n;

    if (!buffer_can_read(buff)) {
        return ERROR;
    }

    ptr = buffer_read_ptr(buff, &count);
    n   = write(client_fd, ptr, count);
    if (n > 0) {
        buffer_read_adv(buff, n);
        selector_set_interest_key(key, OP_READ);
    } else {
        ret = ERROR;
    }
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// AUTH_READ
////////////////////////////////////////////////////////////////////////////////

static unsigned
auth_process(struct selector_key *key, struct request_st *r);

/** inicializa las variables de los estados HELLO_… */
static void
auth_read_init(const unsigned state, struct selector_key *key) {
    struct request_st *r = &ATTACHMENT(key)->request;
    r->hpcp_parser->state = hpcp_request_cmd;
}

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned
auth_read(struct selector_key *key) {
    struct request_st       *r    = &ATTACHMENT(key)->request;
    unsigned                ret   = AUTH_READ;
    bool                    error = false;
    struct buffer           *buff = r->rb;
    enum hpcp_request_state st;
    uint8_t                 *ptr;
    size_t                  count;
    ssize_t                 n;

    if (!buffer_can_write(buff)) {
        return ERROR;
    }

    ptr = buffer_write_ptr(buff, &count);
    n   = read(*r->client_fd, ptr, count);
    if (n > 0) {
        buffer_write_adv(buff, n);
        st = hpcp_request_consume(buff, r->hpcp_parser, &error);
        if (hpcp_request_is_done(st, &error)) {
            ret = auth_process(key, r);
        }
    } else {
        ret = ERROR;
    }
    return ret;
}

/** procesamiento del mensaje `hello' */
static unsigned
auth_process(struct selector_key *key, struct request_st *r) { // recivo error y proceso la respuesta
    struct buffer *buff = r->wb;
    struct hpcp_request *request = &r->request;
    if (request->nargs != CMD_AUTH_NARGS) {
        printf("invalid hello args\n");
        return hpcp_request_error_invalid_args;
    }
    buffer_write(buff, hpcp_status_ok);
    buffer_write(buff, 0x00);
    selector_set_interest_key(key, OP_WRITE);
    return AUTH_WRITE;
}

////////////////////////////////////////////////////////////////////////////////
// AUTH_WRITE
////////////////////////////////////////////////////////////////////////////////

/** escribe todos los bytes de la respuesta al mensaje `hello' */
static unsigned
auth_write(struct selector_key *key) {
    int           client_fd = ATTACHMENT(key)->client_fd;
    struct buffer *buff     = &ATTACHMENT(key)->write_buffer;
    unsigned      ret       = COMAND_READ;
    uint8_t       *ptr;
    size_t        count;
    ssize_t       n;

    if (!buffer_can_read(buff)) {
        return ERROR;
    }

    ptr = buffer_read_ptr(buff, &count);
    n   = write(client_fd, ptr, count);
    if (n > 0) {
        buffer_read_adv(buff, n);
        selector_set_interest_key(key, OP_READ);
    } else {
        ret = ERROR;
    }
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// CMD_READ
////////////////////////////////////////////////////////////////////////////////

static unsigned
cmd_process(struct selector_key *key, struct request_st *request);

/** inicializa las variables de los estados HELLO_… */
static void
cmd_read_init(const unsigned state, struct selector_key *key) {
    struct request_st *r = &ATTACHMENT(key)->request;
    r->hpcp_parser->state = hpcp_request_cmd;
}

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned
cmd_read(struct selector_key *key) {
    struct request_st       *r    = &ATTACHMENT(key)->request;
    unsigned                ret   = COMAND_READ;
    bool                    error = false;
    struct buffer           *buff = r->rb;
    enum hpcp_request_state st;
    uint8_t                 *ptr;
    size_t                  count;
    ssize_t                 n;

    if (!buffer_can_write(buff)) {
        return ERROR;
    }

    ptr = buffer_write_ptr(buff, &count);
    n   = read(*r->client_fd, ptr, count);
    if (n > 0) {
        buffer_write_adv(buff, n);
        st = hpcp_request_consume(buff, r->hpcp_parser, &error);
        if (hpcp_request_is_done(st, &error)) {
            ret = cmd_process(key, r);
        }
    } else {
        ret = ERROR;
    }
    return ret;
}

static unsigned
cmd_process(struct selector_key *key, struct request_st *r) { // recibo error y proceso la respuesta
    struct buffer *buff = r->wb;
    struct hpcp_request *request = &r->request;
    switch (request->cmd) {
        case hpcp_request_cmd_close:
            return cmd_close_process(request);
        case hpcp_request_cmd_get:
            return cmd_get_process(request);
        case hpcp_request_cmd_set:
            return cmd_set_process(request);
        default:
            return ERROR;
    }
}

static unsigned cmd_close_process(struct hpcp_request *request) {
    if (request->nargs != CMD_CLOSE_NARGS) {
        return ERROR;
    }
    return COMAND_WRITE;
}

static unsigned cmd_get_process(struct hpcp_request *request) {
    //el primer argumento es de un byte y diferencia entre get configurations y get metrics
    if (request->nargs < CMD_GET_MIN_NARGS || request->args_sizes[0] != 0x01) {
        return ERROR;
    }
    switch (request->args[0][0]) {
        case CONFIGURATIONS:
            return cmd_get_configurations_process(request);
        case METRICS:
            return cmd_get_metrics_process(request);
        default:
            return ERROR;
    }
}

static unsigned cmd_get_configurations_process(struct hpcp_request *request) {
    if (request->nargs != 0x02 || request->args_sizes[1] != 0x01) {
        return ERROR;
    }
    switch (request->args[1][0]) {
        case TRANSFORMATION_PROGRAM:
            return get_transformation_program(request);
        case TRANSFORMATION_PROGRAM_STATUS:
            return get_transformation_program_status(request);
        case MEDIA_TYPES:
            return get_media_types(request);
        default:
            return ERROR;
    }
}

static unsigned get_transformation_program(struct hpcp_request *request) {
    return COMAND_WRITE;
}

static unsigned get_transformation_program_status(struct hpcp_request *request) {
    return COMAND_WRITE;
}

static unsigned get_media_types(struct hpcp_request *request) {
    return COMAND_WRITE;
}

static unsigned cmd_get_metrics_process(struct hpcp_request *request) {
    if (request->nargs != 0x02 || request->args_sizes[1] != 0x01) {
        return ERROR;
    }
    switch (request->args[1][0]) {
        case CONCURRENT_CONNECTIONS:
            return get_concurrent_connections(request);
        case HISTORIC_ACCESSES:
            return get_historic_accesses(request);
        case TRANSFERRED_BYTES:
            return get_transferred_bytes(request);
        default:
            return ERROR;
    }
}

static unsigned get_concurrent_connections(struct hpcp_request *request) {
    return COMAND_WRITE;
}

static unsigned get_historic_accesses(struct hpcp_request *request) {
    return COMAND_WRITE;
}

static unsigned get_transferred_bytes(struct hpcp_request *request) {
    return COMAND_WRITE;
}

static unsigned cmd_set_process(struct hpcp_request *request) {
    if (request->nargs < CMD_SET_MIN_NARGS || request->args_sizes[0] != 0x01) {
        return ERROR;
    }
    switch (request->args[0][0]) {
        case CONFIGURATIONS:
            return cmd_set_configurations_process(request);
        default:
            return ERROR;
    }
}

static unsigned cmd_set_configurations_process(struct hpcp_request *request) {
    if (request->args_sizes[1] != 0x01) {
        return ERROR;
    }
    switch (request->args[1][0]) {
        case TRANSFORMATION_PROGRAM:
            return set_transformation_program(request);
        case TRANSFORMATION_PROGRAM_STATUS:
            return set_transformation_program_status(request);
        case MEDIA_TYPES:
            return set_media_types(request);
        default:
            return ERROR;
    }
}

static unsigned set_transformation_program(struct hpcp_request *request) {

    return COMAND_WRITE;
}

static unsigned set_transformation_program_status(struct hpcp_request *request) {
    return COMAND_WRITE;
}

static unsigned set_media_types(struct hpcp_request *request) {
    return COMAND_WRITE;
}


////////////////////////////////////////////////////////////////////////////////
// CMD_WRITE
////////////////////////////////////////////////////////////////////////////////

/** escribe todos los bytes de la respuesta al mensaje `hello' */
static unsigned
cmd_write(struct selector_key *key) {
    int           client_fd = ATTACHMENT(key)->client_fd;
    struct buffer *buff     = &ATTACHMENT(key)->write_buffer;
    unsigned      ret       = AUTH_READ;
    uint8_t       *ptr;
    size_t        count;
    ssize_t       n;

    if (!buffer_can_read(buff)) {
        return ERROR;
    }

    ptr = buffer_read_ptr(buff, &count);
    n   = write(client_fd, ptr, count);
    if (n > 0) {
        buffer_read_adv(buff, n);
        selector_set_interest_key(key, OP_READ);
    } else {
        ret = ERROR;
    }
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST_ERROR
////////////////////////////////////////////////////////////////////////////////

static unsigned
request_error_write(struct selector_key *key) {
    int                client_fd = ATTACHMENT(key)->client_fd;
    struct buffer      *buff     = &ATTACHMENT(key)->write_buffer;
    enum socks_v5state ret       = ATTACHMENT(key)->state_before_error;
    uint8_t            *ptr;
    size_t             count;
    ssize_t            n;

    if (!buffer_can_read(buff)) {
        return ERROR;
    }

    ptr = buffer_read_ptr(buff, &count);
    n   = write(client_fd, ptr, count);
    if (n > 0) {
        buffer_read_adv(buff, n);
        selector_set_interest_key(key, OP_READ);
    } else {
        ret = ERROR;
    }
    return ret;
}

void
cmd_close(int client_fd, struct buffer *buff) {
    uint8_t *ptr;
    size_t  count;
    ssize_t n;

    // todo: estoy asumiendo que no quedo nada pendiente por enivar, cuando haga un read voy a ler 0x0x0
    buffer_write(buff, hpcp_status_ok);
    buffer_write(buff, 0);
    ptr = buffer_read_ptr(buff, &count);
    n   = write(client_fd, ptr, count);
    if (n > 0) {
        buffer_read_adv(buff, n);
    }

}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
        {
                .state            = HELLO_READ,
                .on_arrival       = hello_read_init,
                .on_read_ready    = hello_read,
                .on_departure     = on_read_departure,
        },
        {
                .state            = HELLO_WRITE,
                .on_write_ready   = hello_write,
        },
        {
                .state            = AUTH_READ,
                .on_arrival       = auth_read_init,
                .on_read_ready    = auth_read,
                .on_departure     = on_read_departure,
        },
        {
                .state            = AUTH_WRITE,
                .on_write_ready   = auth_write,
        },
        {
                .state            = COMAND_READ,
                .on_arrival       = cmd_read_init,
                .on_read_ready    = cmd_read,
                .on_departure     = on_read_departure,
        },
        {
                .state            = COMAND_WRITE,
                .on_write_ready   = cmd_write,
        },
        {
                .state            = REQUEST_ERROR,
                .on_write_ready   = request_error_write,
        },
        {
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
socksv5_done(struct selector_key *key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine     *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st   = stm_handler_read(stm, key);

    if (ERROR == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine     *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st   = stm_handler_write(stm, key);

    if (ERROR == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine     *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st   = stm_handler_block(stm, key);

    if (ERROR == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key *key) {
    const int     fds[] = {
            ATTACHMENT(key)->client_fd,
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
