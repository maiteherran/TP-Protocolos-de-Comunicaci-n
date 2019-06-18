#include <memory.h>
#include "auth.h"
#include <string.h>

int
log_in(char *username, size_t user_size, char *password, size_t pass_size) {
    return (strncmp(username, user, user_size) == 0) && (strncmp(password, pass, pass_size) == 0);
}