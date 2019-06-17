#include <memory.h>
#include <stdio.h>
#include <ctype.h>
#include "http_parser.h"

static const char   *CRLF          = "\r\n";
static const char   *HOST_HEADER_M = "Host";
static const size_t CRLF_LENGTH    = 2;

char *ltrim(char *s) {
    while (isspace(*s)) s++;
    return s;
}

char *rtrim(char *s) {
    char *back = s + strlen(s);
    while (isspace(*--back));
    *(back + 1) = '\0';
    return s;
}

char *trim(char *s) {
    return rtrim(ltrim(s));
}

int check_host_in_url(struct request_parser *p) {
    int            iport;
    unsigned short cport = 80;
    char           hostaux[BUFFER_SIZE], pathaux[BUFFER_SIZE];
    if (strncasecmp(p->url, "http://", 7) == 0) {
        strncpy(p->url, "http", 4);
        if (sscanf(p->url, "http://%[^:/]:%d%s", hostaux, &iport, pathaux) == 3)
            cport = (unsigned short) iport;
        else if (sscanf(p->url, "http://%[^/]%s", hostaux, pathaux) == 2) {
        } else if (sscanf(p->url, "http://%[^:/]:%d", hostaux, &iport) == 2) {
            cport = (unsigned short) iport;
            *pathaux       = '/';
            *(pathaux + 1) = '\0';
        } else if (sscanf(p->url, "http://%[^/]", hostaux) == 1) {
            cport = 80;
            *pathaux       = '/';
            *(pathaux + 1) = '\0';
        } else {
            printf("Bad request\n");
            return 0;
        }
        p->request->port = cport;
        strcpy(p->request->host, hostaux);
        return 1;
    }
    p->request->port     = 80;
    return 0;
}

void
get_host_and_port_(struct request_parser *p) {
    char aux[BUFFER_SIZE];
    int port;
    if (sscanf(p->request->host, "%[^:]:%d", aux, &port) == 2) {
        p->request->port = port;
    } else if (sscanf(p->request->host, "%[^:]", aux) == 1) {  // no hay puerto, solo host. Tomamos como default el puerto 80
        p->request->port = 80;
    }
    strcpy(p->request->host, aux);
}

static void
remaining_set(struct request_parser *p, int n) {
    p->i = 0;
    p->n = n;
}

static int
remaining_is_done(struct request_parser *p) {
    return p->i >= p->n;
}

static enum request_state
header(const uint8_t c, struct request_parser *p) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-') {
        p->header[p->i++] = c;
        return request_header;
    } else if (c == ' ') {
        return request_header;
    } else if (":") {
        p->header[p->i++] = '\0';
        if (strcasecmp(trim(p->header), "Host") == 0) { // no hay nada a que hacer trim no?
            remaining_set(p, BUFFER_SIZE);
            return request_header_host;
        }
        return request_header_value;
    }
    return request_error;
}

static enum request_state
header_host(const uint8_t c, struct request_parser *p) {
    enum request_state next;
    switch (c) {
        case '\r':
            get_host_and_port_(p);
            next = request_done;
            break;
        default:
            if (c != ' ') {
                p->request->host[p->i++] = c;
            }
            next = request_header_host;
    }
    return next;
}

static enum request_state
crlf(const uint8_t c, struct request_parser *p) {
    if (p->i < CRLF_LENGTH) {
        if (c != CRLF[p->i++]) {
            return request_error;
        }
        return request_crlf;
    }
    remaining_set(p, BUFFER_SIZE);
    return header(c, p);
}

static enum request_state
header_value(const uint8_t c, struct request_parser *p) {
    enum request_state next;
    switch (c) {
        case '\r':
            remaining_set(p, CRLF_LENGTH);
            next = crlf(c, p);
            break;
        default: // el valor de este header no me interesa
            next = request_header_value;
    }
    return next;
}

static enum request_state
version(const uint8_t c, struct request_parser *p) {
    enum request_state next;
    switch (c) {
        case '\r':
            remaining_set(p, CRLF_LENGTH);
            next = crlf(c, p);
            break;
        default: // si hay algun espacio no me interesa espero el fin de linea
            next = request_version;
    }
    return next;
}

static enum request_state
spaces_before_version(const uint8_t c, struct request_parser *p) {
    enum request_state next;
    switch (c) {
        case ' ':
            next = request_spaces_before_version;
            break;
        default:
            next = version(c, p);
    }
    return next;
}

static enum request_state
method(const uint8_t c, struct request_parser *p) {
    if ((c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z')) { //no puede arrancar con espacios, lo probe con netcat a google y me reboto
        return request_method;
    } else if (c == ' ') {
        return request_spaces_before_url;
    }
    return request_error;
}

static enum request_state
url(const uint8_t c, struct request_parser *p) {
    enum request_state next;
    switch (c) {
        case ' ': // aca termino el url, chequeamos si ya esta el host ahi
            if (check_host_in_url(p)) {
                next = request_done;
                break;
            }
            next = request_spaces_before_version;
            break;
        default: // caracteres de la url
            if (!remaining_is_done(p)) { // mientras que no se haya llenado el buffer
                p->url[p->i++] = c;
                next = request_url;
            } else {
                next = request_error;
            }
            break;
    }
    return next;
}

static enum request_state
spaces_before_url(const uint8_t c, struct request_parser *p) {
    enum request_state next;
    switch (c) {
        case ' ':
            next = request_spaces_before_url;
            break;
        default: // encontre un caracter, debe ser parte de la url
            remaining_set(p, BUFFER_SIZE); //TODO: este bufffer siza
            next = url(c, p);
    }
    return next;
}

extern enum request_state
request_parser_feed(struct request_parser *p, const uint8_t c) {
    enum request_state next;
    switch (p->state) {
        case request_method:
            next = method(c, p);
            break;
        case request_spaces_before_url:
            next = spaces_before_url(c, p);
            break;
        case request_url:
            next = url(c, p);
            break;
        case request_spaces_before_version:
            next = spaces_before_version(c, p);
            break;
        case request_version:
            next = version(c, p);
            break;
        case request_crlf:
            next = crlf(c, p);
            break;
        case request_header:
            next = header(c, p);
            break;
        case request_header_value:
            next = header_value(c, p);
            break;
        case request_header_host:
            next = header_host(c, p);
            break;
        case request_done:
        case request_error:
        case request_error_unsupported_version:
            next = p->state;
            break;
        default:
            next = request_error;
            break;
    }
    return p->state = next;
}

extern bool
request_is_done(const enum request_state st, bool *errored) {
    if (st >= request_error && errored != 0) {
        *errored = true;
    }
    return st == request_done;
}

extern enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored) {
    enum request_state st = p->state;
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = request_parser_feed(p, c);
        if (request_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern void
request_parser_init(struct request_parser *p) {
    p->state = request_method;
    p->i     = 0;
    memset(p->request, 0, sizeof(*(p->request)));
}

extern void
request_close(struct request_parser *p) {
    // nada que hacer
}
