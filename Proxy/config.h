#ifndef PROBANDOTPPROTOS_COMANDS_H
#define PROBANDOTPPROTOS_COMANDS_H

#include "../Utils/buffer.h"
#include "../Admin/HpcpParser/hpcpRequest.h"

typedef struct {
    char     *transformation_program;
    unsigned transformation_on;
    char     *media_types;
    char     *error_file;
} conf;

//conf proxy_configurations;
#endif //PROBANDOTPPROTOS_COMANDS_H
