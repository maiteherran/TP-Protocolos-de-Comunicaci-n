//
// Created by Fermin Gomez on 6/13/19.
//

#ifndef PROBANDOTPPROTOS_COMANDS_H
#define PROBANDOTPPROTOS_COMANDS_H

#include "../Utils/buffer.h"
#include "HpcpParser/hpcpRequest.h"

typedef struct {
    char * transformation_program;
    unsigned transformation_on;
    char **media_types;
    int n_media_types;
} conf;

conf proxy_configurations;
#endif //PROBANDOTPPROTOS_COMANDS_H
