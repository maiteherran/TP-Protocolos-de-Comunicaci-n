#include "include/client.h"

static bool            done        = false;
static char            *address    = DEF_ADDRESS;
static uint16_t        port        = DEF_PORT;
static uint8_t         version     = DEF_VERSION;
static uint8_t         sub_version = DEF_SUB_VERS;
static char            buffer[MAX_BUFFER];
static struct addrinfo *addr_info;
static int             socket_fd;
static bool            logged      = false;
static char            *username;
static char            *password;

static uint16_t parse_port(const char *port);

static void show_options();

static void set_up_server(int argc, char **argv);

static bool get_address(const char *address, uint16_t port, struct addrinfo **addr_info_res);

static bool get_auth(const char *username, const char *password);

static void show_commands();

static void get_configurations();

static void get_metrics();

static void set_configurations();

static void quit();

static void show_datagram(uint8_t *datagram, unsigned size);

static void show_error(uint8_t error_code);

static void get_transformation_program();

static void get_transformation_status();

static void get_media_types();

static void get_concurrent_connections();

static void get_historical_accesses();

static void get_transferred_bytes();

static void get_metric(uint8_t metric);

static void set_transformation_program();

static void set_transformation_status();

static void set_media_types();

static void log_in();

static void get_command();

static bool hello();

static void parse_version(const char *optarg);

static void init_connection(int argc, char *argv[], bool already_initiated);

static void restart_connection();

static void show_connection_error();

static void free_resources();

// TODO: liberar todos los recursos, incluso en caso de error

int main(int argc, char *argv[]) {

    init_connection(argc, argv, false);

    printf("\nSuccess! You are connected to %s:%hu.\n\n", address, port);

    while (!done) {

        /** Autentificamos al usuario si no está loggeado */
        if (!logged) {
            log_in();
        }

        /** Mostramos los comandos disponibles */
        show_commands();

        /** Leemos el comando elegido */
        get_command();

    }

    free_resources();
    exit(EXIT_SUCCESS);
}

static void init_connection(int argc, char *argv[], bool already_initiated) {

    if (!already_initiated) {

        /**
         * Si el usuario pasó como parámetro la dirección y el puerto
         * del server para la configuración, y la versión que puede utilizar,
         * lo guardamos en @address, @port y @version
         */
        set_up_server(argc, argv);

        /**
         * Obtenemos la dirección del administrador del server
         */
        if (!get_address(address, port, &addr_info)) {
            fprintf(stderr, "Error: could not resolve address %s:%hu", address, port);
            exit(EXIT_FAILURE);
        }
    }

    /**
     * Creamos un socket al server
     */
    socket_fd = socket(addr_info->ai_family, SOCK_STREAM, IPPROTO_SCTP);
    if (socket_fd < 0) {
        fprintf(stderr, "Error: could not create communication with the server at %s:%hu.\n%s", address, port,
                strerror(errno));      // todo: esta bien el mensaje?
        exit(EXIT_FAILURE);
    }

    /**
     * Tratamos de conectarnos con el server
     */
    if (connect(socket_fd, addr_info->ai_addr, addr_info->ai_addrlen) < 0) {
        fprintf(stderr, "Error: could not connect with the server at %s:%hu.", address,
                port);                   // todo: esta bien el mensaje?
        exit(EXIT_FAILURE);
    }

    /** Saludamos al servidor y negociamos la versión a utilizar */
    bool resolve_version = hello();
    if (!resolve_version) {
        exit(EXIT_FAILURE);
    }

}

static void restart_connection() {

    /** Intentamos reconectarnos con el server
     * Si hay algún error va a ocurrir un exit
     */
    init_connection(-1, NULL, true);

    /** Como ya nos había mandado sus credenciales, lo autentificamos. */
    if (!get_auth(username, password)) {
        exit(EXIT_FAILURE);
    }
    logged = true;
}

static bool hello() {

    uint8_t cmd, n_args, arglen1, arg1, arg2, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
    cmd     = HELLO_CMD;
    n_args  = 1;
    arglen1 = 2;
    arg1    = version;
    arg2    = sub_version;

    datagram[0] = cmd;
    datagram[1] = n_args;
    datagram[2] = arglen1;
    datagram[3] = arg1;
    datagram[4] = arg2;

    int ret;
    ret = sctp_sendmsg(socket_fd, (const void *) datagram, 5, NULL, 0, 0, 0, STREAM, 0, 0);

    if (ret == -1 || ret == 0) {
        show_connection_error();
    }

    ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
    /*resp[0] = 0;
    resp[1] = 0;*/

    if (ret == -1 || ret == 0) {
        show_connection_error();
    }

    if (resp[0] == 0) {
        return true;
    }

    show_error(resp[1]);
    return false;
}

static void log_in() {

    printf("Please login in order to continue\n");
    char user[MAX_BUFFER], pass[MAX_BUFFER];

    printf("Username: ");
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        sscanf(buffer, "%s", user);
    } else {
        printf("Please enter your username\n");
    }

    printf("Password: ");
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        sscanf(buffer, "%s", pass);
        logged = get_auth(user, pass);
    } else {
        printf("Please enter your password\n");
    }

    if (!logged) {
        exit(EXIT_FAILURE);
    }

    username = malloc(strlen(user) + 1);
    password = malloc(strlen(pass) + 1);
    memcpy(username, user, strlen(user));
    username[strlen(user)] = '\0';
    memcpy(password, pass, strlen(pass));
    password[strlen(pass)] = '\0';
}

static void get_command() {

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {

        unsigned long ul = strtoul(buffer, NULL, 10);

        switch (ul) {
            case 1:
                get_configurations();
                break;
            case 2:
                get_metrics();
                break;
            case 3:
                set_configurations();
                break;
            case 4:
                show_commands();
                break;
            case 5:
                quit();
                break;
            default:
                printf("Error: Unrecongnized option %lu", ul);
                break;
        }

    } else {
        printf("Please enter a command. For help enter 0.\n");
    }
}

static void set_up_server(int argc, char **argv) {

    int c;

    while ((c = getopt(argc, argv, ":L:o:v:")) != -1) {
        switch (c) {
            case 'L':
                address = malloc(strlen(optarg) + 1);
                memcpy(address, optarg, strlen(optarg) + 1);
                break;
            case 'o':
                port = parse_port(optarg);
                break;
            case 'v':
                parse_version(optarg);
                break;
            case ':':       /* -a o -p o -v sin argumento */
                fprintf(stderr, "Error: Option -%c requires an argument\n", optopt);
                exit(EXIT_FAILURE);
            case '?':
                fprintf(stderr, "Error: Unrecognized option '-%c'\n", optopt);
                exit(EXIT_FAILURE);
            default:
                show_options();
                exit(EXIT_FAILURE);
        }
    }
}

static void parse_version(const char *optarg) {

    sscanf(optarg, "%hhu.%hhu", &version, &sub_version);
}

static uint16_t parse_port(const char *port) {

    if (*port == '-') {
        fprintf(stderr, "Error: '-p' argument %s must be positive\n", port);
        exit(EXIT_FAILURE);
    }

    int res = 0;

    while (isdigit(*port)) {
        res = res * 10 + (*port++ - '0');
    }

    if (*port != '\0' && !isdigit(*port)) {
        fprintf(stderr, "Error: '-p' argument %s is not an integer\n", port);
        exit(EXIT_FAILURE);
    } else if (res < MIN_PORT || res > MAX_PORT) {
        fprintf(stderr, "Error: '-p' argument %s is not an integer between %u and %u\n", port, MIN_PORT, MAX_PORT);
        exit(EXIT_FAILURE);
    }

    return (uint16_t) res;
}

static bool get_address(const char *address, uint16_t port, struct addrinfo **addr_info_res) {

    struct addrinfo addr_info_hints = {
            .ai_family    = AF_UNSPEC,    /* Allow IPv4 or IPv6 */
            .ai_socktype  = SOCK_STREAM,
            .ai_flags     = AI_PASSIVE,   /* For wildcard IP address */
            .ai_protocol  = 0,            /* Any protocol */
            .ai_canonname = NULL,
            .ai_addr      = NULL,
            .ai_next      = NULL,
    };

    char port_to_string[15];
    snprintf(port_to_string, sizeof(port_to_string), "%hu", port);

    return getaddrinfo(address, port_to_string, &addr_info_hints, addr_info_res) == 0;
}

static bool get_auth(const char *username, const char *password) {

    uint8_t cmd, n_args, arglen1, arglen2, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
    cmd    = AUTH_CMD;
    n_args = 2;

    if (strlen(username) > 255) {
        printf("Username is too long.\n");
        return false;
    }
    if (strlen(password) > 255) {
        printf("Password is too long.\n");
        return false;
    }

    arglen1 = (uint8_t) strlen(username);
    arglen2 = (uint8_t) strlen(password);

    datagram[0] = cmd;
    datagram[1] = n_args;
    datagram[2] = arglen1;

    for (int i = 0; i < arglen1; i++) {
        datagram[i + 3] = (uint8_t) username[i];
    }

    datagram[arglen1 + 3] = arglen2;

    for (int j = 0; j < arglen2; j++) {
        datagram[j + 4 + arglen1] = (uint8_t) password[j];
    }

    int ret;
    ret = sctp_sctp_sendmsgmsg(socket_fd, (const void *) datagram, arglen1 + arglen2 + 4, NULL, 0, 0, 0, STREAM, 0, 0);

    if (ret == -1 || ret == 0) {
        show_connection_error();
    }

    ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
    /*resp[0] = 4;
    resp[1] = 0;*/

    if (ret == -1 || ret == 0) {
        show_connection_error();
    }

    if (resp[0] == 0) {
        return true;
    }

    show_error(resp[0]);
    return false;
}

static void get_configurations() {
    printf("\nSelect from the following configurations:\n");
    printf("1 --> Transformation program\n");
    printf("2 --> Transformation program status\n");
    printf("3 --> Media types\n");
    // todo: elegir mas de una configuracion al mismo tiempo

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {

        unsigned long ul = strtoul(buffer, NULL, 10);

        switch (ul) {
            case 1:
                get_transformation_program();
                break;
            case 2:
                get_transformation_status();
                break;
            case 3:
                get_media_types();
                break;
            default:
                printf("Error: Unrecongnized option %lu", ul);
                break;
        }

    } else {
        fprintf(stderr, "Please enter a command.\n");
    }
}

static void get_metrics() {
    printf("\nSelect from the following metrics:\n");
    printf("\t1 --> Concurrent connections\n");
    printf("\t2 --> Historical accesses\n");
    printf("\t3 --> Transferred bytes\n");
    // todo: elegir mas de una metrica al mismo tiempo

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {

        unsigned long ul = strtoul(buffer, NULL, 10);

        switch (ul) {
            case 1:
                get_concurrent_connections();
                break;
            case 2:
                get_historical_accesses();
                break;
            case 3:
                get_transferred_bytes();
                break;
            default:
                printf("Error: Unrecongnized option %lu", ul);
                break;
        }

    } else {
        fprintf(stderr, "Please enter a command.\n");
    }
}

static void get_transferred_bytes() {
    get_metric(GET_BYTES);
}

static void get_historical_accesses() {
    get_metric(GET_HIST);
}

static void get_concurrent_connections() {
    get_metric(GET_CONN);
}

static void get_metric(uint8_t metric) {
    uint8_t cmd, n_args, arglen1, arg1, arglen2, arg2, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
    cmd     = GET_CMD;
    arg1    = GET_METRICS;
    arg2    = metric;
    arglen1 = 1;
    arglen2 = 1;
    n_args  = 2;
    datagram[0] = cmd;
    datagram[1] = n_args;
    datagram[2] = arglen1;
    datagram[3] = arg1;
    datagram[4] = arglen2;
    datagram[5] = arg2;

    int ret;
    ret = sctp_sendmsg(socket_fd, (const void *) datagram, 6, NULL, 0, 0, 0, STREAM, 0, 0);

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);

    /*resp[0] = 0;
    resp[1] = 1;
    resp[2] = 4;
    int number = 400000000;
    resp[3] = (uint8_t) (number & 0xFF);
    resp[4] = (uint8_t) ((number >> 8) & 0xFF);
    resp[5] = (uint8_t) ((number >> 16) & 0xFF);
    resp[6] = (uint8_t) ((number >> 24) & 0xFF);*/

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    if (resp[0] == 0) {

        uint64_t acum = 0;
        for (int i    = 0; i < resp[2]; i++) {
            acum += (resp[3 + i] << (8 * (resp[2] - 1 - i)));
        }

        switch (metric) {
            case GET_CONN:
                printf("Concurrent connections: %llu\n", acum);
                break;
            case GET_HIST:
                printf("Historical accesses: %llu\n", acum);
                break;
            case GET_BYTES:
                printf("Transferred bytes: %llu\n", acum);
                break;
            default:
                printf("Metric #%hhu: %llu\n", metric, acum);
                break;
        }

    } else {
        show_error(resp[1]);
    }
}

static void set_configurations() {
    printf("\nSelect from the following configurations:\n");
    printf("\t1 --> Transformation program\n");
    printf("\t2 --> Transformation program status\n");
    printf("\t3 --> Media types\n");

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {

        unsigned long ul = strtoul(buffer, NULL, 10);

        switch (ul) {
            case 1:
                set_transformation_program();
                break;
            case 2:
                set_transformation_status();
                break;
            case 3:
                set_media_types();
                break;
            default:
                break;
        }

    } else {
        fprintf(stderr, "Please enter a command.\n");
    }

}

static void set_media_types() {

    printf("Please enter a media type or press 'q' to exit:\n");

    uint8_t cmd, n_args, arglen1, arg1, arglen2, arg2, arglen3, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];

    cmd     = SET_CMD;
    arg1    = SET_CONF;
    arg2    = SET_MEDIA;
    arglen1 = 1;
    arglen2 = 1;
    n_args  = 2;
    datagram[0] = cmd;
    datagram[2] = arglen1;
    datagram[3] = arg1;
    datagram[4] = arglen2;
    datagram[5] = arg2;
    int      index = 6;
    unsigned size  = 6;

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {

        if (strlen(buffer) > 255) {
            printf("Please enter a shorter type.\n");
            return;
        }

        arglen3 = (uint8_t)(strlen(buffer) - 1);
        buffer[arglen3]   = '\0';
        datagram[index++] = arglen3;

        for (int i = 0; i < strlen(buffer); i++) {
            datagram[index + i] = (uint8_t) buffer[i];
        }

        n_args++;
        index += arglen3;
        size += (arglen3 + 1);


        datagram[1] = n_args;

        int ret;
        ret = sctp_sendmsg(socket_fd, (const void *) datagram, size, NULL, 0, 0, 0, STREAM, 0, 0);

        if (ret == -1 || ret == 0) {
            restart_connection();
        }

        ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
        /*resp[0] = 0;
        resp[1] = 0;*/

        if (ret == -1 || ret == 0) {
            restart_connection();
        }

        if (resp[0] == 0) {
            printf("\nSuccess!\n");

        } else {
            printf("\n");
            show_error(resp[1]);
        }
    } else {
        fprintf(stderr, "Please enter a command.\n");
    }
}

static void set_transformation_status() {

    printf("Please enter a status (0/1): ");

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {

        unsigned long ul = strtoul(buffer, NULL, 10);

        if (ul > 1) {
            printf("\nError: Unrecognized option %lu.\n", ul);
            return;
        }

        uint8_t cmd, n_args, arglen1, arg1, arglen2, arg2, arglen3, arg3, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
        cmd     = SET_CMD;
        arg1    = SET_CONF;
        arg2    = SET_TRANSF_STAT;
        arg3    = (uint8_t) ul;
        arglen1 = 1;
        arglen2 = 1;
        arglen3 = 1;
        n_args  = 3;
        datagram[0] = cmd;
        datagram[1] = n_args;
        datagram[2] = arglen1;
        datagram[3] = arg1;
        datagram[4] = arglen2;
        datagram[5] = arg2;
        datagram[6] = arglen3;
        datagram[7] = arg3;

        int ret;
        ret = sctp_sendmsg(socket_fd, (const void *) datagram, 8, NULL, 0, 0, 0, STREAM, 0, 0);

        if (ret == -1 || ret == 0) {
            restart_connection();
        }

        ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
        /*resp[0] = 0;
        resp[1] = 0;*/

        if (ret == -1 || ret == 0) {
            restart_connection();
        }

        if (resp[0] == 0) {
            printf("\nSuccess! Transformation program status is now %lu\n", ul);

        } else {
            printf("\n");
            show_error(resp[1]);
        }
    } else {
        fprintf(stderr, "Please enter a command.\n");
    }
}

static void set_transformation_program() {

    printf("Please enter the name of the trasnformation program: ");

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {

        if (strlen(buffer) > 255) {
            printf("Please enter a shorter name.\n");
            return;
        }

        uint8_t cmd, n_args, arglen1, arg1, arglen2, arg2, arglen3, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
        cmd     = SET_CMD;
        arg1    = SET_CONF;
        arg2    = SET_TRANSF_PRGM;
        arglen1 = 1;
        arglen2 = 1;
        arglen3 = (uint8_t)(strlen(buffer) - 1);
        buffer[arglen3] = '\0';
        n_args = 3;
        datagram[0] = cmd;
        datagram[1] = n_args;
        datagram[2] = arglen1;
        datagram[3] = arg1;
        datagram[4] = arglen2;
        datagram[5] = arg2;
        datagram[6] = arglen3;
        for (int i = 0; i < strlen(buffer); i++) {
            datagram[7 + i] = (uint8_t) buffer[i];
        }

        int ret;
        ret = sctp_sendmsg(socket_fd, (const void *) datagram, 7 + arglen3, NULL, 0, 0, 0, STREAM, 0, 0);

        if (ret == -1 || ret == 0) {
            restart_connection();
        }

        ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
        /*resp[0] = 0;
        resp[1] = 0;*/

        if (ret == -1 || ret == 0) {
            restart_connection();
        }

        if (resp[0] == 0) {
            printf("\nSuccess! Transformation program is now %s\n", buffer);

        } else {
            printf("\n");
            show_error(resp[1]);
        }


    } else {
        fprintf(stderr, "Please enter a command.\n");
    }

}

static void quit() {

    uint8_t cmd, n_args, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
    cmd    = CLOSE_CMD;
    n_args = 0;

    datagram[0] = cmd;
    datagram[1] = n_args;

    int ret;
    ret = sctp_sendmsg(socket_fd, (const void *) datagram, 2, NULL, 0, 0, 0, STREAM, 0, 0);

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
    /*resp[0] = 0;
    resp[1] = 1;*/

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    if (resp[0] == 0) {
        exit(EXIT_SUCCESS);
    }

    show_error(resp[1]);
}

static void get_transformation_program() {
    uint8_t cmd, n_args, arglen1, arg1, arglen2, arg2, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
    cmd     = GET_CMD;
    arg1    = GET_CONF;
    arg2    = GET_TRANSF_PRGM;
    arglen1 = 1;
    arglen2 = 1;
    n_args  = 2;
    datagram[0] = cmd;
    datagram[1] = n_args;
    datagram[2] = arglen1;
    datagram[3] = arg1;
    datagram[4] = arglen2;
    datagram[5] = arg2;

    int ret;
    ret = sctp_sendmsg(socket_fd, (const void *) datagram, 6, NULL, 0, 0, 0, STREAM, 0, 0);

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
    /*resp[0] = 0;
    resp[1] = 1;
    resp[2] = 14;
    resp[3] = 'P';
    resp[4] = 'r';
    resp[5] = 'o';
    resp[6] = 'g';
    resp[7] = 'r';
    resp[8] = 'a';
    resp[9] = 'm';
    resp[10] = 'a';
    resp[11] = 'a';
    resp[12] = 'a';
    resp[13] = 'X';
    resp[14] = 'X';
    resp[15] = 'X';
    resp[16] = 'X';*/

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    if (resp[0] == 0) {
        char *name = malloc(resp[2] + 1);
        memcpy(name, resp + 3, resp[2]);
        printf("Transformation program: %s\n", name);
        free(name);
    } else {
        show_error(resp[1]);
    }
}

static void get_transformation_status() {
    uint8_t cmd, n_args, arglen1, arg1, arglen2, arg2, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
    cmd     = GET_CMD;
    arg1    = GET_CONF;
    arg2    = GET_TRANSF_STAT;
    arglen1 = 1;
    arglen2 = 1;
    n_args  = 2;
    datagram[0] = cmd;
    datagram[1] = n_args;
    datagram[2] = arglen1;
    datagram[3] = arg1;
    datagram[4] = arglen2;
    datagram[5] = arg2;

    int ret;
    ret = sctp_sendmsg(socket_fd, (const void *) datagram, 6, NULL, 0, 0, 0, STREAM, 0, 0);

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
    /*resp[0] = 0;
    resp[1] = 1;
    resp[2] = 1;
    resp[3] = 0;*/

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    if (resp[0] == 0) {
        printf("Transformation program: ");
        if (resp[3]) {
            printf("active\n");
        } else {
            printf("inactive\n");
        }
    } else {
        show_error(resp[1]);
    }
}

static void get_media_types() {
    uint8_t cmd, n_args, arglen1, arg1, arglen2, arg2, datagram[MAX_DATAGRAM], resp[MAX_DATAGRAM];
    cmd     = GET_CMD;
    arg1    = GET_CONF;
    arg2    = GET_MEDIA;
    arglen1 = 1;
    arglen2 = 1;
    n_args  = 2;
    datagram[0] = cmd;
    datagram[1] = n_args;
    datagram[2] = arglen1;
    datagram[3] = arg1;
    datagram[4] = arglen2;
    datagram[5] = arg2;

    int ret;
    ret = sctp_sendmsg(socket_fd, (const void *) datagram, 6, NULL, 0, 0, 0, STREAM, 0, 0);

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    ret = sctp_recvmsg(socket_fd, (void *) resp, MAX_DATAGRAM, (struct sockaddr *) NULL, 0, 0, 0);
    /*resp[0] = 0;
    resp[1] = 3;
    resp[2] = 4;
    resp[3] = 'j';
    resp[4] = 'p';
    resp[5] = 'e';
    resp[6] = 'g';
    resp[7] = 3;
    resp[8] = 'p';
    resp[9] = 'n';
    resp[10] = 'g';
    resp[11] = 3;
    resp[12] = 'p';
    resp[13] = 'd';
    resp[14] = 'f';*/

    if (ret == -1 || ret == 0) {
        restart_connection();
    }

    if (resp[0] == 0) {
        int pos = 0;
        printf("Media types:\n");
        char     *aux = malloc(ARG_LEN_MAX);
        for (int i    = 0; i < resp[1]; i++) {
            memcpy(aux, resp + 3 + i + pos, resp[pos + 2 + i]);
            aux[resp[pos + 2 + i]] = '\0';
            printf("%s\n", aux);
            pos += resp[pos + 2 + i];
        }
        free(aux);
    } else {
        show_error(resp[1]);
    }
}

static void show_datagram(uint8_t *datagram, unsigned size) {

    printf("DATAGRAM:\n");
    for (int i = 0; i < size; i++) {
        printf("%hhu\t", datagram[i]);
    }
    printf("\n");
}

static void show_error(uint8_t error_code) {

    switch (error_code) {
        case 1:
            printf("Error: Try again.\n");
            break;
        case 2:
            printf("Error: Invalid command.\n");
            break;
        case 3:
            printf("Error: Invalid arguments.\n");
            break;
        case 4:
            printf("Error: Wrong credentials.\n");
            break;
        case 5:
            printf("Error: Inexistant transformation program.\n");
            break;
        case 6:
            printf("Error: Version.\n");
            break;
        default:
            break;
    }
}

static void show_connection_error() {

    printf("Oops! A connection error has occured between you and the server. Please try again later.\n");
    exit(EXIT_FAILURE);
}

static void show_commands() {
    printf("\nSelect from the following commands:\n");
    printf("\t1 --> Get configurations\n");
    printf("\t2 --> Get metrics\n");
    printf("\t3 --> Set configurations\n");
    printf("\t4 --> Help\n");
    printf("\t5 --> Quit\n");
}

static void show_options() {
    printf("Welcome to the HPCP client interface\n\n");
    printf("Your options are:\n\n");
    printf("-%c management-address\n", 'L');
    printf("\tSets the address where the management service is serving. By default it listens in loopback.\n");
    printf("-%c management-port\n", 'o');
    printf("\tSTCP port where the management server is located. By default port is 9090.\n");
    printf("-%c protocol-version\n", 'v');
    printf("\tProtocol version of the configuration administrator.\n");
}

static void free_resources() {

    free(address);
    free(username);
    free(password);
}