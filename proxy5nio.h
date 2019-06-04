#ifndef proxy5NIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm
#define proxy5NIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm

#include <netdb.h>
#include "Utils/selector.h"
#include "Parser/picohttpparser.h"

/** handler del socket pasivo que atiende conexiones proxyv5 */
void
proxyv5_passive_accept(struct selector_key *key);


/** libera pools internos */
void
proxyv5_pool_destroy(void);

#endif
