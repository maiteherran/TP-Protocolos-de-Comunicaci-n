#include "server_arguments.h"

server_args_ptr args;

static void show_options();

static void init_args();

static void parse_version(const char *optarg);

static uint16_t parse_port(const char *port);

static void print_arguments();

server_args_ptr read_arguments(int argc, const char *argv[]) {

    init_args();

    int c;

    while ((c = getopt(argc, argv, ":e:h:l:L:M:o:p:t:v:")) != -1) {
        switch (c) {
            case 'e':
                args->error_file = malloc(strlen(optarg) + 1);
                memcpy(args->error_file, optarg, strlen(optarg) + 1);
                break;
            case 'h':
                show_options();
                exit(EXIT_SUCCESS);
            case 'l':
                args->http_address = malloc(strlen(optarg) + 1);
                memcpy(args->http_address, optarg, strlen(optarg) + 1);
                break;
            case 'L':
                args->admin_address = malloc(strlen(optarg) + 1);
                memcpy(args->admin_address, optarg, strlen(optarg) + 1);
                break;
            case 'M':
                args->media_types = malloc(strlen(optarg) + 1);
                memcpy(args->media_types, optarg, strlen(optarg) + 1);
                break;
            case 'o':
                args->admin_port = parse_port(optarg);
                break;
            case 'p':
                args->http_port = parse_port(optarg);
                break;
            case 't':
                args->cmd = malloc(strlen(optarg) + 1);
                memcpy(args->cmd, optarg, strlen(optarg) + 1);
                break;
            case 'v':
                printf("Version: %hhu.%hhu\n", args->version, args->sub_version);
                exit(EXIT_SUCCESS);
            case '?':
                if (optopt == 'e' || optopt == 'l' || optopt == 'L' || optopt == 'M' || optopt == 'o' ||
                    optopt == 'p' || optopt == 't') {
                    fprintf(stderr, "Error: Option -%c requires an argument\n", optopt);
                    exit(EXIT_FAILURE);
                } else {
                    fprintf(stderr, "Error: Unrecognized option '-%c'\n", optopt);
                    exit(EXIT_FAILURE);
                }
            default:
                show_options();
                exit(EXIT_FAILURE);
        }
    }

    print_arguments();

    return args;
}

static void init_args() {

    args = malloc(sizeof(server_args));

    args->http_address  = DEF_HTTP_ADDRESS;
    args->admin_address = DEF_ADMIN_ADDRESS;
    args->admin_port    = DEF_ADMIN_PORT;
    args->http_port     = DEF_HTTP_PORT;
    args->error_file    = DEF_ERROR_FILE;
    args->version       = DEF_VERSION;
    args->sub_version   = DEF_SUB_VERS;
    args->cmd           = NULL; // vacio o en null?
    args->media_types   = NULL; // vacio o en null?
}

static void parse_version(const char *optarg) {

    sscanf(optarg, "%hhu.%hhu", &args->version, &args->sub_version);
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

static void show_options() {

    printf("Welcome to HTTPD - Proxy HTTP that allows you to transform the body of the responses.\n");
    printf("Your options are:\n");
    printf("-%c file-error\n", 'e');
    printf("\tSpecifies the file where stderr is redirected from the executions of the filters. By default the file is /dev/null.\n");
    printf("-%c\n", 'h');
    printf("\tShows options available and terminates.\n");
    printf("-%c http-address\n", 'l');
    printf("\tSets the address where the HTTP proxy is serving. By default it listens on all interfaces.\n");
    printf("-%c management-address\n", 'L');
    printf("\tSets the address where the management service is serving. By default it listens in loopback.\n");
    printf("-%c transformable-media-types\n", 'M');
    printf("\tList of transformable media types. The syntax of the list follows the rules of the HTTP Accept header (section 5.3.2 of RFC7231). By default the list is empty.\n");
    printf("-%c management-port\n", 'o');
    printf("\tSTCP port where the management server is located. By default port is 9090.\n");
    printf("-%c local-port\n", 'p');
    printf("\tTCP port listening for incoming HTTP connections. By default port is 8080.\n");
    printf("-%c cmd\n", 't');
    printf("\tCommand used for external transformations. Compatible with system(3).\n");
    printf("-%c\n", 'v');
    printf("\tShows information about the version and terminates.\n");

}

static void print_arguments() {

    printf("Arguments:\n");
    printf("-%c %s\n", 'e', args->error_file);
    printf("-%c\n", 'h');
    printf("-%c %s\n", 'l', args->http_address);
    printf("-%c %s\n", 'L', args->admin_address);
    printf("-%c %s\n", 'M', args->media_types);
    printf("-%c %hu\n", 'o', args->admin_port);
    printf("-%c %hu\n", 'p', args->http_port);
    printf("-%c %s\n", 't', args->cmd);
    printf("-%c\n", 'v');
}
