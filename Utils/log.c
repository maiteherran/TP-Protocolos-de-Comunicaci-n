#include "log.h"

static const char * types[] = {
        "ACCES", "WARN", "ERROR", "DEBUG"
};

static const char * files[] = {
        "logs/acces.log", "logs/warning.log", "logs/error.log", "logs/debug.log"
};


static struct logger_t {
    int     on;
    int     fds[DEBUG+1];
} l;

void logger_init() {
    l.on = 1;
    for(int i = 0; i < DEBUG+1; i++) {
        l.fds[i] = open(files[i], O_RDWR | O_CREAT);
    }
}

void logger_off() {
    l.on = 0;
}

void logger_on() {
    l.on = 1;
}

void logger(int fd, const char * type ,const char *fmt, va_list args) {
    time_t now;
    time(&now);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0'; // ctime devuelve en este formato: Thu Nov 24 18:22:48 1986\n\0 sacamos el '\n'

    printf("%s - [%s] ", type, date);
    vprintf(fmt, args);
    printf("\n");

//    dprintf(fd, "%s - [%s] ", type, date);
//    vdprintf(fd, fmt, args);
//    dprintf(fd, "\n");
}

void log_error(const char *fmt, ...) {
    if (!l.on) { return;}
    va_list args;
    va_start(args, fmt);
    logger(l.fds[ERR], types[ERR], fmt, args);
    va_end(args);
}

void log_acces(const char *fmt, ...) {
    if (!l.on) { return;}
    va_list args;
    va_start(args, fmt);
    logger(l.fds[ERR], types[ACC], fmt, args);
    va_end(args);
}

void log_debug(const char *fmt, ...) {
    if (!l.on) { return;}
    va_list args;
    va_start(args, fmt);
    logger(l.fds[ERR], types[DEBUG], fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    if (!l.on) { return;}
    va_list args;
    va_start(args, fmt);
    logger(l.fds[ERR], types[WARN], fmt, args);
    va_end(args);
}
