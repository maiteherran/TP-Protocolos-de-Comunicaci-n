//
// Created by Fermin Gomez on 6/13/19.
//

#ifndef PROBANDOTPPROTOS_ADMIN_H
#define PROBANDOTPPROTOS_ADMIN_H

#ifndef SOCKS5NIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm
#define SOCKS5NIO_H_whVj9DjZzFKtzEUtC0Ma2Ae45Hm

#include <netdb.h>
#include "../Utils/selector.h"
#include "HpcpParser/hpcpRequest.h"

/** handler del socket pasivo que atiende conexiones socksv5 */
void
socksv5_passive_accept(struct selector_key *key);


/** libera pools internos */
void
socksv5_pool_destroy(void);

static unsigned cmd_close_process(struct hpcp_request *request);
static unsigned cmd_get_process(struct hpcp_request *request);
static unsigned cmd_set_process(struct hpcp_request *request);
static unsigned cmd_get_configurations_process(struct hpcp_request *request);
static unsigned cmd_get_metrics_process(struct hpcp_request *request);
static unsigned get_transformation_program(struct hpcp_request *request);
static unsigned get_transformation_program_status(struct hpcp_request *request);
static unsigned get_media_types(struct hpcp_request *request);
static unsigned get_concurrent_connections(struct hpcp_request *request);
static unsigned get_historic_accesses(struct hpcp_request *request);
static unsigned get_transferred_bytes(struct hpcp_request *request);
static unsigned cmd_set_configurations_process(struct hpcp_request *request);
static unsigned set_transformation_program(struct hpcp_request *request);
static unsigned set_transformation_program_status(struct hpcp_request *request);
static unsigned set_media_types(struct hpcp_request *request);

#endif


#endif //PROBANDOTPPROTOS_ADMIN_H
