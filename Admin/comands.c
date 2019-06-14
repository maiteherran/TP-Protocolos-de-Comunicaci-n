//
// Created by Fermin Gomez on 6/13/19.
//

#include "comands.h"


void
cmd_close(int client_fd, struct buffer *buff) {
    uint8_t *ptr;
    size_t  count;
    ssize_t n;

    // todo: estoy asumiendo que no quedo nada pendiente por enivar, cuando haga un read voy a ler 0x0x0
    buffer_write(buff, hpcp_status_ok);
    buffer_write(buff, 0);
    ptr = buffer_read_ptr(buff, &count);
    n   = write(client_fd, ptr, count);
    if (n > 0) {
        buffer_read_adv(buff, n);
    }

}
