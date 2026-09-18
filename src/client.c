/* client.c: Minimal command-line test client that sends a URL to the proxy and saves the response to disk. */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "request_parser.h"
#include "util.h"

#define PROXY_HOST "127.0.0.1"
#define PROXY_PORT 8080
#define READ_CHUNK_SIZE 8192

static int connect_to_proxy(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("client: socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PROXY_PORT);
    if (inet_pton(AF_INET, PROXY_HOST, &addr.sin_addr) != 1) {
        fprintf(stderr, "client: invalid proxy address\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("client: connect to proxy");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return fd;
}

/* Derives a safe output filename from the URL's host, e.g.
 * http://example.com/path -> example.com.html. Falls back to a generic
 * name if the host can't be extracted cleanly. Bounds every copy by
 * out_len so a hostile/overlong URL can never overflow out. */
static void derive_output_filename(const char *url, char *out, size_t out_len) {
    const char *host_start = strstr(url, "://");
    host_start = host_start ? host_start + 3 : url;

    size_t i = 0;
    while (host_start[i] != '\0' && host_start[i] != '/' && host_start[i] != ':' &&
           host_start[i] != '?' && host_start[i] != '#' && i + 6 < out_len) {
        out[i] = host_start[i];
        i++;
    }

    if (i == 0) {
        snprintf(out, out_len, "response.html");
        return;
    }
    memcpy(out + i, ".html", 6); /* 5 chars + the null terminator */
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <http-url>\n", argv[0]);
        return 2;
    }

    char filename[300];
    derive_output_filename(argv[1], filename, sizeof(filename));

    FILE *out = fopen(filename, "wb");
    if (!out) {
        perror("client: fopen");
        return 2;
    }

    int proxy_fd = connect_to_proxy();

    char request_line[MAX_URL_LEN + 2];
    int req_len = snprintf(request_line, sizeof(request_line), "%s\n", argv[1]);
    if (req_len < 0 || send_all(proxy_fd, request_line, (size_t)req_len) < 0) {
        fprintf(stderr, "client: failed to send request to proxy\n");
        fclose(out);
        close(proxy_fd);
        return 1;
    }

    /* Read in fixed-size chunks and write each one immediately with
     * fwrite() -- the response is arbitrary binary data (not necessarily
     * text), so this must not assume it's safe to treat as a C string or
     * print with printf(). */
    char chunk[READ_CHUNK_SIZE];
    ssize_t n;
    size_t total = 0;
    while ((n = recv(proxy_fd, chunk, sizeof(chunk), 0)) > 0) {
        fwrite(chunk, 1, (size_t)n, out);
        total += (size_t)n;
    }

    fclose(out);
    close(proxy_fd);

    if (n < 0) {
        fprintf(stderr, "client: error reading response from proxy\n");
        return 1;
    }

    printf("Saved response to %s (%zu bytes)\n", filename, total);
    return 0;
}
