//
// Created by Fermin Gomez on 6/13/19.
//

#ifndef PROBANDOTPPROTOS_METRICS_H
#define PROBANDOTPPROTOS_METRICS_H

#include <stdint.h>

typedef struct {
    unsigned long long concurrent_connections;
    unsigned long long historic_accesses;
    unsigned long long transferred_bytes;

} metrics;

unsigned long long concurrent_connections();

unsigned long long historic_accesses();

unsigned long long transferred_bytes();

#endif //PROBANDOTPPROTOS_METRICS_H
