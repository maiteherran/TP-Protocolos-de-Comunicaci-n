#ifndef CLIENTHPCP_PROXY_ARGUMENTS_H
#define CLIENTHPCP_PROXY_ARGUMENTS_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#define DEF_HTTP_ADDRESS "0.0.0.0"
#define DEF_ADMIN_ADDRESS "127.0.0.1"
#define DEF_HTTP_PORT 8080
#define DEF_ADMIN_PORT 9090
#define DEF_ERROR_FILE "/dev/null"
#define DEF_VERSION 1
#define DEF_SUB_VERS 1
#define MAX_PORT 65535
#define MIN_PORT 0

typedef struct server_args {

    char * error_file;              /** Path al error file */
    char * http_address;            /** Direccion del proxy http */
    char * admin_address;           /** Direccion del admin */
    char * media_types;             /** Media types transformables */
    uint16_t admin_port;            /** Puerto del admin */
    uint16_t http_port;             /** Puerto del proxy http */
    char * cmd;                     /** Comando para las tranformaciones externas */
    uint8_t version;                /** Version */
    uint8_t sub_version;

} server_args;

typedef server_args * server_args_ptr;

server_args_ptr read_arguments(int argc, const char *argv[]);

#endif
