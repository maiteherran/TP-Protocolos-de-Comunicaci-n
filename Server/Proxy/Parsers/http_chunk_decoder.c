//FORMATO DE CHUNKS:
/*
      chunked-body   = *chunk
      last-chunk
            trailer-part
            CRLF

    chunk          = chunk-size [ chunk-ext ] CRLF
    chunk-data CRLF
    chunk-size     = 1*HEXDIG
    last-chunk     = 1*("0") [ chunk-ext ] CRLF
    chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
    chunk-ext-name = token
    chunk-ext-val  = token | quoted-string
    chunk-data     = chunk-size(OCTET)
          trailer        = *(entity-header CRLF)

            chunk-data     = 1*OCTET ; a sequence of chunk-size octets
          trailer-part   = *( header-field CRLF )
*/
/*
  https://tools.ietf.org/html/rfc7230#section-4.1.2
     length := 0
     read chunk-size, chunk-ext (if any), and CRLF
     while (chunk-size > 0) {
        read chunk-data and CRLF
        append chunk-data to decoded-body
        length := length + chunk-size
        read chunk-size, chunk-ext (if any), and CRLF
     }
     read trailer field
     while (trailer field is not empty) {
        if (trailer field is allowed to be sent in a trailer) {
            append trailer field to existing header fields
        }
        read trailer-field
     }
     Content-Length := length
     Remove "chunked" from Transfer-Encoding
     Remove Trailer from existing header fields
 */

#include <assert.h>
#include <memory.h>
#include "http_chunk_decoder.h"


static const char   *CRLF       = "\r\n";
static const size_t CRLF_LENGTH = 2;

static int decode_hex(int ch) {
    if ('0' <= ch && ch <= '9') {
        return ch - '0';
    } else if ('A' <= ch && ch <= 'F') {
        return ch - 'A' + 0xa;
    } else if ('a' <= ch && ch <= 'f') {
        return ch - 'a' + 0xa;
    } else {
        return -1;
    }
}

unsigned int
decode_chunk_size(struct phr_chunked_decoder *decoder, char **src) {
    char *c = *src;
    int  v;
    if ((v = decode_hex(*c)) == -1) {
        if (decoder->hex_count == 0) {
            return CHUNK_ERROR;
        } else {
            decoder->hex_count = 0;
            return CHUNK_EXTESION;
        }
    }
    if (decoder->hex_count == sizeof(size_t) * 2) {
        return CHUNK_ERROR;
    }
    decoder->bytes_left_in_chunk = decoder->bytes_left_in_chunk * 16 + v; // cuento la cantidad de bytes en el chunk
    ++decoder->hex_count;
    (*src)++;
    return CHUNK_SIZE;
}

unsigned int
decode_chunk_data(struct phr_chunked_decoder *decoder, char **src, char **dst, char *end) {
    // aca solo hay body, no me interesa su contenido
    if ((end - *src) > decoder->bytes_left_in_chunk) { // se mandaron 2 chunks juntos
        memmove(*dst, *src, decoder->bytes_left_in_chunk); //movemos pisando el chunk_size
        *src += decoder->bytes_left_in_chunk;
        *dst += decoder->bytes_left_in_chunk;
        decoder->bytes_left_in_chunk = 0;
        decoder->aux                 = 0;
        return CHUNK_CRLF;
    } else { //falta data del chunk para consumir
        memmove(*dst, *src, (end - *src)); //muevo para adelante la data
        decoder->bytes_left_in_chunk -= (end - *src);
        *dst += (end - *src);
        *src += (end - *src);
        return CHUNK_DATA;
    }
}

unsigned int
decode_chunk_crlf(struct phr_chunked_decoder *decoder, char **src) {
    //solo avanza src ya que esto tiene que ser borrado para "des chunkear"
    char *c = *src;
    if (decoder->aux < CRLF_LENGTH) {
        if (*c != CRLF[decoder->aux++]) {
            return CHUNK_ERROR;
        }
        (*src)++;
        return CHUNK_CRLF;
    }
    return CHUNK_SIZE;
}

unsigned int
decode_chunk_extension(struct phr_chunked_decoder *decoder, char **src) {
    char *c = *src;
    if (*c == '\n') {
        (*src)++;
        if (decoder->bytes_left_in_chunk == 0) {
            decoder->aux = 0;
            return CHUNK_TRAILER_CRLF; // eliminamos trailers si es que las hay, sino nos encontraremos con un '\r\n' indicando el final
        } else { // no es el final del mensaje
            return CHUNK_DATA;
        }
    }
    (*src)++;
    return CHUNK_EXTESION;
}

unsigned int
decode_chunk_trailer_crlf(struct phr_chunked_decoder *decoder, char **src, char *end) {
    char *c = *src;
    if (decoder->aux < CRLF_LENGTH && *c == CRLF[decoder->aux]) {
        decoder->aux++;
        if (decoder->aux == CRLF_LENGTH) {
            return CHUNK_DONE; // encontramos el '\r\n' final
        }
        (*src)++;
        return CHUNK_TRAILER_CRLF;
    } else if (0 < decoder->aux && decoder->aux < CRLF_LENGTH && *c != CRLF[decoder->aux]) {
        return CHUNK_ERROR;
    }
    (*src)++;
    return CHUNK_TRAILER_FIELD; // quedan trailer headers por sacar
}

unsigned int
decode_chunk_trailer_field(struct phr_chunked_decoder *decoder, char **src) {
    // me salteo el contenido hasta encontrar el final, entonces pasamos a verificar que no haya mas nada por recibir, (si encontramos el '\r\n' final)
    char *c = *src;
    if (*c == '\n') {
        (*src)++;
        decoder->aux = 0;
        return CHUNK_TRAILER_CRLF;
    }
    (*src)++;
    return CHUNK_TRAILER_FIELD;
}

ssize_t decode_chunked(struct phr_chunked_decoder *decoder, char *buf, size_t *buff_size) {
    size_t size = *buff_size;
    char   *dst = buf;
    char   *src = buf;
    char   *end = buf + size;
    while (src != end) {
        switch (decoder->state) {
            case CHUNK_SIZE:
                decoder->state = decode_chunk_size(decoder, &src);
                break;
            case CHUNK_EXTESION:
                decoder->state = decode_chunk_extension(decoder, &src);
                break;
            case CHUNK_CRLF:
                decoder->state = decode_chunk_crlf(decoder, &src);
                break;
            case CHUNK_DATA:
                decoder->state = decode_chunk_data(decoder, &src, &dst, end);
                break;
            case CHUNK_TRAILER_CRLF:
                decoder->state = decode_chunk_trailer_crlf(decoder, &src, end);
                break;
            case CHUNK_TRAILER_FIELD:
                decoder->state = decode_chunk_trailer_field(decoder, &src);
                break;
            case CHUNK_DONE:
                goto finally;
            case CHUNK_ERROR:
                goto ret_value;
            default:
                break;
        }
    }
    finally:
    if (dst != src) {
        memmove(dst, src, (end - src));
    }
    *buff_size = (dst - buf);
    ret_value:
    switch (decoder->state) {
        case CHUNK_DONE:
            return 1;
        case CHUNK_ERROR:
            return -1;
        default:
            return 0;
    }
}
