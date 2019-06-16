#ifndef PROBANDOTPPROTOS_COMANDS_H
#define PROBANDOTPPROTOS_COMANDS_H

#include "../Utils/buffer.h"
#include "../Admin/HpcpParser/hpcpRequest.h"

typedef struct {
    char     *transformation_program;
    unsigned transformation_on;
    char     *media_types;
} conf;

//conf proxy_configurations;
#endif //PROBANDOTPPROTOS_COMANDS_H
