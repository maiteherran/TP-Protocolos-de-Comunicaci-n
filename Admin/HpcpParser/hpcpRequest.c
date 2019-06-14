#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../../Utils/buffer.h"
#include "hpcpRequest.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

extern enum hpcp_request_state hpcp_request_consume (buffer *b, struct hpcp_request_parser *p, bool *errored) {
    printf("FUNCION: request_consume. p->state = %d\n", p->state);
    enum hpcp_request_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        printf("parseando byte: %d\n", c);
        st = hpcp_request_parser_feed(p, c);
        if (hpcp_request_is_done (st, errored)) {
            break;
        }
    }
    printf ("\nno hay nada mas en el buffer\n");
    printf("hpcp_request_state final: %d", st);
    return st;
}

extern enum hpcp_request_state hpcp_request_parser_feed (struct hpcp_request_parser* p, const uint8_t c) {
    enum hpcp_request_state next;

    switch (p->state) {
        case hpcp_request_cmd:
            printf("case cmd state\n");
            next = cmd_parser(c, p);
            printf("exiting case cmd state. p->request_cmd_state = %d", p->request->cmd);
            break;
        case hpcp_request_nargs:
            printf("case nargs state\n");
            next = nargs_parser(c, p);
            printf("exiting case nargs state. p->nargs = %d , p->current_arg = %d\n", p->nargs, p->current_arg);
            break;
        case hpcp_request_current_arglen:
            printf("case current_arglen state\n");
            next = current_arglen_parser(c, p);
            printf("p->current_arg_size = %d , p->current_arg_read_bytes = %d\n", p->current_arg_size, p->current_arg_read_bytes);
            break;
        case hpcp_request_current_arg:
            printf("case hpcp_request_current_arg\n");
            next = current_arg_parser(c, p);
            printf("exiting hpcp_request_current_arg state\n");
            break;
        case hpcp_request_done:
        case hpcp_request_error:
        case hpcp_request_error_unsupported_version:
        case hpcp_request_error_invalid_cmd:
        case hpcp_request_error_invalid_args:
        case hpcp_request_error_invalid_credentials:
        case hpcp_request_error_invalid_transformation_program:
            printf("state: %d\n", p->state);
            next = p->state;
            break;
        default:
            next = hpcp_request_error;
            break;
    }
    return p->state = next;
}


static enum hpcp_request_state cmd_parser (const uint8_t c, struct hpcp_request_parser* p) {
    printf("funcion cmd_parser\n");
    p->request->cmd = c;
    //Retorna el state al que pasa el parser dado que no hubo error en este estado.
    return hpcp_request_nargs;
}

static enum hpcp_request_state nargs_parser(const uint8_t c, struct hpcp_request_parser *p) {
    nargs_initializer (c, p);
    if (c == 0x00 ) {
        return hpcp_request_done;
    }
    return hpcp_request_current_arglen;
}

static void nargs_initializer(const uint8_t c, struct hpcp_request_parser *p) {
    p->nargs = c;
    p->request->nargs = c;
    p->current_arg = 0;
    p->request->args = malloc(c*sizeof(uint8_t*));
    p->request->args_sizes = malloc(c*sizeof(size_t));
}

static enum hpcp_request_state current_arglen_parser (const uint8_t c, struct hpcp_request_parser *p) {
    p->current_arg_size = c;
    p->current_arg_read_bytes = 0;

    p->request->args_sizes[p->current_arg] = (size_t) c;
    p->request->args[p->current_arg] = malloc (c);

    return hpcp_request_current_arg;
}

extern void free_hpcp_request(struct hpcp_request * request) {
    for (int i = 0; i < request->nargs ; i++ ) {
        free (request->args[i]);
    }
    free (request->args);
    free (request->args_sizes);
}

static enum hpcp_request_state current_arg_parser (const uint8_t c, struct hpcp_request_parser *p) {
    printf("FUNCION current_arg_parser\n");
    printf("p->current_arg = %d , p->current_arg_read_bytes = %d\n",p->current_arg,p->current_arg_read_bytes );
    p->request->args[p->current_arg][p->current_arg_read_bytes++] = c;
    if(p->current_arg_read_bytes >= p->current_arg_size) { //se terminó de parsear el argumento
        printf("se termino de parsear el argumento\n");
        p->current_arg++;
        if (p->nargs > p->current_arg) { //le faltan parsear argumentos
            printf("le faltan parsear argumentos\n");
            return hpcp_request_current_arglen;
        }
        printf("no hay mas argumentos q parsear\n");
        printf("\nRequest is done:\n");
        printf("p->request->cmd = %d\n", p->request->cmd);
        printf("args: \n");
        for (int j = 0; j < p->nargs ; j++ ){
            printf("arg %d: length = %d , data = ", j, (int) p->request->args_sizes[j]);
            for (int i = 0; i < p->request->args_sizes[j] ; i++ ) {
                printf("%d", p->request->args[j][i]);
            }
            printf("\n");
        }
        return hpcp_request_done;
    }
    printf("le falta terminar de parsear este argumento\n");
    return hpcp_request_current_arg; //todavia no terminó de parsear al current arg
}

extern bool hpcp_request_is_done(const enum hpcp_request_state st, bool *errored) {
    if(st >= hpcp_request_error && errored != 0) {
        *errored = true;
    }
    return st >= hpcp_request_done;
}



