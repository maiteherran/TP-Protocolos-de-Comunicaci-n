#ifndef PROBANDOTPPROTOS_AUTH_H
#define PROBANDOTPPROTOS_AUTH_H

#include <stdio.h>

/*
 * De esta forma hay solamente un usario y una contrasena, expandirlo a un array de usarios si es necesario manejar mas.
 * Se podria guardar la tupla (user, pass) en una estructura
 */

static const char * user = "admin";
static const char * pass = "admin";

int
log_in(char * username, size_t user_size, char * password, size_t pass_size);

#endif //PROBANDOTPPROTOS_AUTH_H
