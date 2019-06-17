//
// Created by Fermin Gomez on 6/13/19.
//

#ifndef TPPROTOS_METRICS_H
#define TPPROTOS_METRICS_H

#include <stdint.h>

typedef struct {
    unsigned long long concurrent_connections;
    unsigned long long historic_accesses;
    unsigned long long transferred_bytes;
} metrics;

//metrics proxy_metrics;


#endif //TPPROTOS_METRICS_H
