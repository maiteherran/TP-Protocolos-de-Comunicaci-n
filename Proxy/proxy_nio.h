#ifndef proxyNIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm
#define proxyNIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm

#include <netdb.h>
#include "../Utils/selector.h"
#include "Parsers/http_parser.h"

/** handler del socket pasivo que atiende conexiones proxy */
void
proxy_passive_accept(struct selector_key *key);


/** libera pools internos */
void
proxy_pool_destroy(void);

#endif
