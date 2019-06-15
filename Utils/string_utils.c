#include <memory.h>
#include "string_utils.h"

void
strncpy_(char *dst, char *src, int srcsize, int dstsize) {
    int to_cpy = 0;
    if (srcsize >= dstsize) {
        to_cpy = dstsize - 1; // null terminal
    } else {
        to_cpy = srcsize;
    }
    memcpy(dst, src, to_cpy);
    *(dst + to_cpy +1) = '\0';
}
