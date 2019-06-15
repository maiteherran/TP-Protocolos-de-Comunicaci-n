#ifndef PROBANDOTPPROTOS_HTTP_CHUNK_DECODER_H
#define PROBANDOTPPROTOS_HTTP_CHUNK_DECODER_H

#import <stdio.h>

enum chunk_state {
    CHUNK_SIZE, // estado inicial
    CHUNK_EXTESION,
    CHUNK_DATA,
    CHUNK_CRLF,
    CHUNK_TRAILER_FIELD,
    CHUNK_TRAILER_CRLF,
    CHUNK_DONE,
    CHUNK_ERROR
};


struct phr_chunked_decoder {
    size_t           bytes_left_in_chunk;
    char             hex_count;
    enum chunk_state state;
    int              aux;
};

ssize_t decode_chunked(struct phr_chunked_decoder *decoder, char *buff, size_t *buff_size);

#endif //PROBANDOTPPROTOS_HTTP_CHUNK_DECODER_H
