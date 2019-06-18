#ifndef HPCPPARSER0_HPCPREQUEST_H
#define HPCPPARSER0_HPCPREQUEST_H

#include <stdint.h>
#include <stdbool.h>
#include "../../Utils/buffer.h"

/*   The HPCP request is formed as follows:
*
*       +-----+-------+----------+----------+-----+-----------+--------+
*       | CMD |N-ARGS | ARGLEN 1 | ARG1     | ... | ARGLEN N  | ARG N  |
*       +-----+-------+----------+----------+-----+-----------+--------+
*       |  1  |   1   |  1       | Variable | ... | 1         |Variable|
*       +-----+-------+----------+----------+-----+-----------+--------+
*
*   Dónde:
*
CMD
HELLO 0X00
AUTH 0x01
CLOSE 0x02
GET 0x03
SET 0x04

N-ARGS: indica la cantidad de argumentos .
ARGLEN i: indica la longitud del argumento i. Como este campo tiene asignado un byte, la longitud máxima de un argumento es 2^8 = 256.
ARG i: argumento i con longitud ARGLEN i.

*/
enum hpcp_response_status {
    hpcp_status_ok                             = 0x00,
    hpcp_status_error                          = 0x01,
    hpcp_status_invalid_command                = 0x02,
    hpcp_status_invalid_arguments              = 0x03,
    hpcp_status_invalid_credentials            = 0x04,
    hpcp_status_invalid_transformation_program = 0x05,
    hpcp_status_invalid_version                = 0x06,
};

enum hpcp_request_cmd {
    hpcp_request_cmd_hello = 0x00,
    hpcp_request_cmd_auth  = 0x01,
    hpcp_request_cmd_close = 0x02,
    hpcp_request_cmd_get   = 0x03,
    hpcp_request_cmd_set   = 0x04,
};

struct hpcp_request {
    enum hpcp_request_cmd cmd;
    uint8_t               **args;
    size_t                *args_sizes;
    size_t                nargs;
};

/*Estados en los cuales se puede encontrar el parser*/
enum hpcp_request_state {
    hpcp_request_cmd,
    hpcp_request_nargs,
    hpcp_request_current_arglen,
    hpcp_request_current_arg,

    hpcp_request_done, //4

    //Error
            hpcp_request_error, //5
            hpcp_request_error_unsupported_version, //6
            hpcp_request_error_invalid_cmd, //7
            hpcp_request_error_invalid_args, //8
            hpcp_request_error_invalid_credentials, //9
            hpcp_request_error_invalid_transformation_program, //10
};

struct hpcp_request_parser {
    /*Request que está siendo parseado*/
    struct hpcp_request     *request;
    /*Actual estado del parser*/
    enum hpcp_request_state state;

    /*Cantidad de argumentos*/
    uint8_t nargs;
    /*Bytes leídos*/
    uint8_t n_read_bytes;
    /*Argumento que está siendo parseado*/
    uint8_t current_arg;
    /*Tamaño del argumento que se está leyendo*/
    uint8_t current_arg_size;
    /*Cantidad de bytes leídos del argumento que se está leyendo*/
    uint8_t current_arg_read_bytes;
};


//--//
extern enum hpcp_request_state hpcp_request_consume(buffer *b, struct hpcp_request_parser *p, bool *errored);

extern enum hpcp_request_state hpcp_request_parser_feed(struct hpcp_request_parser *p, uint8_t c);

static enum hpcp_request_state cmd_parser(uint8_t c, struct hpcp_request_parser *p);

static enum hpcp_request_state nargs_parser(uint8_t c, struct hpcp_request_parser *p);

static enum hpcp_request_state current_arglen_parser(uint8_t c, struct hpcp_request_parser *p);

static enum hpcp_request_state current_arg_parser(uint8_t c, struct hpcp_request_parser *p);

extern bool hpcp_request_is_done(enum hpcp_request_state st, bool *errored);

extern void free_hpcp_request(struct hpcp_request *request);

static void nargs_initializer(uint8_t c, struct hpcp_request_parser *p);

static enum hpcp_request_state validate_request(struct hpcp_request *request);

extern int hpcp_response(buffer *b, const enum hpcp_response_status response_status, uint8_t nresp, uint8_t *data_sizes,
                         uint8_t **data);

#endif //HPCPPARSER0_HPCPREQUEST_H