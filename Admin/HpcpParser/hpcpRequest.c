#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../../Utils/buffer.h"
#include "hpcpRequest.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

extern enum hpcp_request_state hpcp_request_consume(buffer *b, struct hpcp_request_parser *p, bool *errored) {
    enum hpcp_request_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = hpcp_request_parser_feed(p, c);
        if (hpcp_request_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern enum hpcp_request_state hpcp_request_parser_feed(struct hpcp_request_parser *p, const uint8_t c) {
    enum hpcp_request_state next;

    switch (p->state) {
        case hpcp_request_cmd:
            next = cmd_parser(c, p);
            break;
        case hpcp_request_nargs:
            next = nargs_parser(c, p);
            break;
        case hpcp_request_current_arglen:
            next = current_arglen_parser(c, p);
            break;
        case hpcp_request_current_arg:
            next = current_arg_parser(c, p);
            break;
        case hpcp_request_done:
        case hpcp_request_error:
        case hpcp_request_error_unsupported_version:
        case hpcp_request_error_invalid_cmd:
        case hpcp_request_error_invalid_args:
        case hpcp_request_error_invalid_credentials:
        case hpcp_request_error_invalid_transformation_program:
            next = p->state;
            break;
        default:
            next = hpcp_request_error;
            break;
    }
    return p->state = next;
}


static enum hpcp_request_state cmd_parser(const uint8_t c, struct hpcp_request_parser *p) {
    p->request->cmd = c;
    //Retorna el state al que pasa el parser dado que no hubo error en este estado.
    return hpcp_request_nargs;
}

static enum hpcp_request_state nargs_parser(const uint8_t c, struct hpcp_request_parser *p) {
    nargs_initializer(c, p);
    if (c == 0x00) {
        return hpcp_request_done;
    }
    return hpcp_request_current_arglen;
}

static void nargs_initializer(const uint8_t c, struct hpcp_request_parser *p) {
    p->nargs               = c;
    p->request->nargs      = c;
    p->current_arg         = 0;
    p->request->args       = malloc(c * sizeof(uint8_t *));
    p->request->args_sizes = malloc(c * sizeof(size_t));
}

static enum hpcp_request_state current_arglen_parser(const uint8_t c, struct hpcp_request_parser *p) {
    p->current_arg_size       = c;
    p->current_arg_read_bytes = 0;

    p->request->args_sizes[p->current_arg] = (size_t) c;
    p->request->args[p->current_arg]       = malloc(c);

    return hpcp_request_current_arg;
}

extern void free_hpcp_request(struct hpcp_request *request) {
    for (int i = 0; i < request->nargs; i++) {
        free(request->args[i]);
    }
    free(request->args);
    free(request->args_sizes);
}

static enum hpcp_request_state current_arg_parser(const uint8_t c, struct hpcp_request_parser *p) {
    p->request->args[p->current_arg][p->current_arg_read_bytes++] = c;
    if (p->current_arg_read_bytes >= p->current_arg_size) { //se terminó de parsear el argumento
        p->current_arg++;
        if (p->nargs > p->current_arg) { //le faltan parsear argumentos
            return hpcp_request_current_arglen;
        }
        for (int j = 0; j < p->nargs; j++) {
            for (int i = 0; i < p->request->args_sizes[j]; i++) {
            }
        }
        return hpcp_request_done;
    }
    return hpcp_request_current_arg; //todavia no terminó de parsear al current arg
}

extern bool hpcp_request_is_done(const enum hpcp_request_state st, bool *errored) {
    if (st >= hpcp_request_error && errored != 0) {
        *errored = true;
    }
    return st >= hpcp_request_done;
}

extern int hpcp_response(buffer *b, const enum hpcp_response_status response_status, uint8_t nresp, uint8_t *data_sizes,
                         uint8_t **data) {
    size_t  n;
    uint8_t *buff                 = buffer_write_ptr(b, &n);
    int     total_response_length = 2; //minimo necesito 2 bytes para el response status y nresp
    if (n < total_response_length) {
        return -1;
    }
    buffer_write(b, response_status);
    buffer_write(b, nresp);
    buffer_write_adv(b, 2);
    for (int i = 0; i < nresp; i++) {
        total_response_length += 1 +
                                 data_sizes[i]; //necesito lugar para el argumento_i que es de longitud data_size[i] y para el data_size del argumento_i que ocupa 1 byte
        if (n < total_response_length) {
            return -1;
        }
        buffer_write(b, data_sizes[i]);
        buffer_write_adv(b, 1);
        for (int j = 0; j < data_sizes[i]; j++) {
            buffer_write(b, data[i][j]);
            buffer_write_adv(b, 1);
        }
    }
    return total_response_length;
}



