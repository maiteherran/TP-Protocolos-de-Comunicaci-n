#ifndef CLIENTHPCP_CLIENT_H
#define CLIENTHPCP_CLIENT_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <stdbool.h>

#define MAX_PORT 65535
#define MIN_PORT 0
#define DEF_ADDRESS "127.0.0.1"
#define DEF_PORT 9090
#define DEF_VERSION 1
#define DEF_SUB_VERS 1
#define MAX_BUFFER 1048576                  // 1 MB = 1048576 B todo: esta bien este tamaño?
#define MAX_DATAGRAM 65282                  // N_ARGS_MAX = 255 = ARG_LENG_MAX--> 255 * 255 + 255 + 2
#define ARG_LEN_MAX 255
#define STREAM 0
#define HELLO_CMD 0x00
#define AUTH_CMD 0x01
#define CLOSE_CMD 0x02
#define GET_CMD 0x03
#define GET_CONF 0x00
#define GET_TRANSF_PRGM 0x01
#define GET_TRANSF_STAT 0x02
#define GET_MEDIA 0x04
#define GET_METRICS 0x01
#define GET_CONN 0x01
#define GET_HIST 0x02
#define GET_BYTES 0x04
#define SET_CMD 0x04
#define SET_CONF 0x00
#define SET_TRANSF_PRGM 0x01
#define SET_TRANSF_STAT 0x02
#define SET_MEDIA 0x04


/**
 * Seguimos los lineamientos de POSIX.1-2008:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getopt.html
 * http://man7.org/linux/man-pages/man3/getaddrinfo.3.html
 */

#endif
