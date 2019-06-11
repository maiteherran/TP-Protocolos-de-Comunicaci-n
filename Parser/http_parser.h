//
// Created by Fermin Gomez on 6/6/19.
//

#ifndef PROBANDOTPPROTOS_HTTP_PARSER_H
#define PROBANDOTPPROTOS_HTTP_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "../Utils/buffer.h"

#define  BUFFER_SIZE 1024

struct request {
    char host[BUFFER_SIZE];
    int  port;
};

enum request_state {
    request_method,
    request_spaces_before_url,
    request_url,
    request_version,
    request_spaces_before_version,
    request_crlf,
    request_header,
    request_header_host,
    request_header_value,
    request_done,
    request_error,
    request_error_unsupported_version,
};

struct request_parser {
    struct request     *request;
    enum request_state state;
    char               url[BUFFER_SIZE];
    char               header[BUFFER_SIZE];
    /** cuantos bytes tenemos que leer*/
    int                n;
    /** cuantos bytes ya leimos */
    int                i;
};


/** inicializa el parser */
void
request_parser_init(struct request_parser *p);

/** entrega un byte al parser. retorna true si se llego al final  */
enum request_state
request_parser_feed(struct request_parser *p, const uint8_t c);

/**
 * por cada elemento del buffer llama a `request_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa socks_hello_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool
request_is_done(const enum request_state st, bool *errored);

void
request_close(struct request_parser *p);

#endif //PROBANDOTPPROTOS_HTTP_PARSER_H
