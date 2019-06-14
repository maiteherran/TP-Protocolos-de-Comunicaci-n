//
// Created by Fermin Gomez on 6/13/19.
//

#include "metrics.h"

void add_connection() {
    proxy_metrics.concurrent_connections++;
}

void remove_connection() {
    proxy_metrics.concurrent_connections--;
}

void add_access() {
    proxy_metrics.historic_accesses++;
}
void add_transferred_bytes(unsigned long long bytes) {
    proxy_metrics.transferred_bytes += bytes;
}

unsigned long long get_concurrent_connections() {
    return proxy_metrics.transferred_bytes;
}

unsigned long long get_access() {
    return proxy_metrics.transferred_bytes;
}
unsigned long long get_transferred_bytes() {
    return proxy_metrics.transferred_bytes;
}


