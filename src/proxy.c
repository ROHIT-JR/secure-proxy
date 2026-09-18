/* proxy.c: Program entry point that starts the listening socket and dispatches accepted connections to worker threads. */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "request_parser.h"

#define LISTEN_PORT 8080
#define REQUEST_LINE_BUF_LEN (MAX_URL_LEN + 3) /* URL + '\r' + '\n' + '\0' */
#define CLIENT_READ_TIMEOUT_SECONDS 5

typedef enum {
    LINE_OK,
    LINE_TOO_LARGE,
    LINE_TIMEOUT,
    LINE_CLOSED,
    LINE_ERROR
} ReadLineStatus;

/* Creates, binds, and starts listening on a TCP socket for LISTEN_PORT.
 * Exits the process on failure, since a listener that can't start has
 * nothing useful to serve. */
static int create_listening_socket(void) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Lets the server rebind immediately after a restart instead of
     * failing with "Address already in use" while the old socket is
     * still in TIME_WAIT. */
    int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(listen_fd, SOMAXCONN) < 0) {
        perror("listen");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    return listen_fd;
}

/* Reads a single newline-terminated request line from client_fd into buf
 * (which must be at least REQUEST_LINE_BUF_LEN bytes), enforcing both a
 * maximum size and a per-read timeout. recv() only guarantees at least
 * one byte per call, so this loops until '\n' is seen, the buffer would
 * overflow, the client disconnects, or the read times out. */
static ReadLineStatus read_request_line(int client_fd, char *buf, size_t buf_len) {
    size_t used = 0;

    while (used + 1 < buf_len) {
        ssize_t n = recv(client_fd, buf + used, 1, 0);

        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return LINE_TIMEOUT;
            }
            if (errno == EINTR) {
                continue;
            }
            return LINE_ERROR;
        }
        if (n == 0) {
            return LINE_CLOSED;
        }

        used += (size_t)n;

        if (buf[used - 1] == '\n') {
            buf[used] = '\0';
            return LINE_OK;
        }
    }

    return LINE_TOO_LARGE;
}

/* Writes a minimal, safe HTTP/1.1 error response and closes nothing itself
 * -- the caller owns the socket and decides when to close it. Sized to
 * comfortably hold the largest possible body (see the 200 OK body buffer
 * in handle_client) plus header boilerplate, so snprintf() can never
 * truncate it. */
static void send_error_response(int client_fd, int status_code, const char *status_text,
                                 const char *body) {
    char response[MAX_HOST_LEN + MAX_PATH_LEN + 256];
    int body_len = (int)strlen(body);

    int written = snprintf(response, sizeof(response),
                            "HTTP/1.1 %d %s\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: %d\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "%s",
                            status_code, status_text, body_len, body);

    if (written > 0) {
        size_t to_send = (size_t)written < sizeof(response) ? (size_t)written : sizeof(response);
        send(client_fd, response, to_send, 0);
    }
}

/* Handles exactly one client connection end to end: read one request line,
 * validate it, and reply. Origin fetching is wired in by Issue #6/#7 --
 * for now a successfully parsed request gets an acknowledgement so this
 * issue's acceptance criteria (valid error or acknowledgement) can be
 * verified with a plain `nc`. */
static void handle_client(int client_fd) {
    struct timeval timeout;
    timeout.tv_sec = CLIENT_READ_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    char line[REQUEST_LINE_BUF_LEN];
    ReadLineStatus status = read_request_line(client_fd, line, sizeof(line));

    switch (status) {
        case LINE_TOO_LARGE:
            send_error_response(client_fd, 413, "Payload Too Large",
                                 "413 Payload Too Large: Request URL exceeds 2048B.\n");
            return;
        case LINE_TIMEOUT:
            send_error_response(client_fd, 408, "Request Timeout",
                                 "408 Request Timeout: No complete request line received.\n");
            return;
        case LINE_CLOSED:
        case LINE_ERROR:
            /* Client disconnected or the socket errored; nothing to reply to. */
            return;
        case LINE_OK:
            break;
    }

    /* Strip the trailing "\r\n" or "\n" before handing the line to the parser. */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }

    ParsedUrl parsed;
    ParseStatus parse_status = parse_http_url(line, &parsed);

    if (parse_status != PARSE_OK) {
        char body[256];
        snprintf(body, sizeof(body), "400 Bad Request: %s\n", parse_status_to_string(parse_status));
        send_error_response(client_fd, 400, "Bad Request", body);
        return;
    }

    /* Sized to comfortably hold the largest possible host (MAX_HOST_LEN)
     * and path (MAX_PATH_LEN) plus the surrounding boilerplate text, so
     * snprintf() can never truncate here. */
    char body[MAX_HOST_LEN + MAX_PATH_LEN + 128];
    snprintf(body, sizeof(body),
             "200 OK: Parsed request for host=%s port=%u path=%s\n"
             "(Origin fetching is implemented in a later issue.)\n",
             parsed.host, parsed.port, parsed.path);
    send_error_response(client_fd, 200, "OK", body);
}

int main(void) {
    /* A client closing its side of the connection must not kill the
     * process with SIGPIPE; failed writes are handled via send()'s
     * return value instead. */
    signal(SIGPIPE, SIG_IGN);

    int listen_fd = create_listening_socket();
    printf("proxy: listening on port %d\n", LISTEN_PORT);
    fflush(stdout); /* stdout is fully buffered when not a tty (e.g. redirected to a log file) */

    while (1) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue; /* one bad accept must not take the listener down */
        }

        handle_client(client_fd);
        close(client_fd);
    }

    close(listen_fd); /* unreachable in this single-threaded skeleton, kept for clarity */
    return 0;
}
