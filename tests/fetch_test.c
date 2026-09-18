/* fetch_test.c: Command-line test harness for the origin fetcher -- resolves and fetches a URL, streaming the raw response into a file. */
#include "origin_client.h"
#include "request_parser.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <http-url> <output-file>\n", argv[0]);
        return 2;
    }

    ParsedUrl url;
    ParseStatus parse_status = parse_http_url(argv[1], &url);
    if (parse_status != PARSE_OK) {
        fprintf(stderr, "fetch_test: invalid URL: %s\n", parse_status_to_string(parse_status));
        return 2;
    }

    int out_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("fetch_test: open");
        return 2;
    }

    FetchStatus fetch_status = fetch_and_relay(&url, out_fd);
    close(out_fd);

    if (fetch_status != FETCH_OK) {
        fprintf(stderr, "fetch_test: %s (would map to 502 Bad Gateway in the proxy)\n",
                fetch_status_to_string(fetch_status));
        return 1;
    }

    printf("fetch_test: OK, response streamed to %s\n", argv[2]);
    return 0;
}
