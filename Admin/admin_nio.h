#ifndef TPPROTOS_ADMIN_H
#define TPPROTOS_ADMIN_H

#include <netdb.h>
#include "../Utils/selector.h"
#include "HpcpParser/hpcpRequest.h"

/** handler del socket pasivo que atiende conexiones hpcp */
void
hpcp_passive_accept(struct selector_key *key);


/** libera pools internos */
void
hpcp_pool_destroy(void);


#endif

