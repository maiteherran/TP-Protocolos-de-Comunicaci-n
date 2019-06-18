#include "proxy_reporter.h"

struct report_t {
    int status_code;
    const char *status_msg;
    const char *headers;
    const char *body;
};

static const struct report_t reports[] = {
        { // CONNECTION
                .status_code = 500,
                .body = "<html><h1>500</h1><body>Could not contact server</body></html>",
                .headers = "Connection: close",
                .status_msg = "TOO BAD",
        },
        { // TRANSFORMATION
                .status_code = 500,
                .body = "<html><h1>500</h1><body>Could not transform content</body></html>",
                .headers = "Connection: close",
                .status_msg = "TOO BAD",
        },
        { // BAD GATEWAY
                .status_code = 502,
                .body = "<html><h1>502</h1><body>Bad Gateway</body></html>",
                .headers = "Connection: close",
                .status_msg = "TOO BAD",
        },
        {  // DNS
                .status_code = 503,
                .body = "<html><h1>503</h1><body>Service Unavailable</body></html>",
                .headers = "Connection: close",
                .status_msg = "TOO BAD",
        },
        { // STORAGE
                .status_code = 507,
                .body = "<html><h1>507</h1><body>Insufficient Storage</body></html>",
                .headers = "Connection: close",
                .status_msg = "TOO BAD",
        },
        {  // BAD REQUEST
                .status_code = 400,
                .body = "<html><h1>400</h1><body>Bad Request</body></html>",
                .headers = "Connection: close",
                .status_msg = "TOO BAD",
        }
};


void
report(int client_fd, enum report r) {
    struct report_t d = reports[r];
    dprintf(client_fd, "HTTP/1.1 %d %s\r\n%s\r\n\r\n%s\r\n\r\n", d.status_code, d.status_msg, d.headers,
            d.body);
}
