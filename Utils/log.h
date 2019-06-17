#ifndef TPPROTOS_LOG_H
#define TPPROTOS_LOG_H

#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>

enum log_types {
    ACC,
    WARN,
    ERR,  // puse ERR ya que hay otro enum con ERROR, se chocan
    DEBUG
};

//const int types_length = DEBUG+1;

void logger_init();

void logger_off();

void logger_on();

void log_error(const char *fmt, ...);

void log_acces(const char *fmt, ...);

void log_debug(const char *fmt, ...);

void log_warn(const char *fmt, ...);

#endif //TPPROTOS_LOG_H
