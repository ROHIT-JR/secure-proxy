/* test_parser.c: Unit tests for safe URL parsing and domain normalisation. */
#include <request_parser.h>
#include <stdio.h>
#include <string.h>

static int total_tests = 0;
static int passed_tests = 0;

static void test_valid(const char *url, const char *expected_host, uint16_t expected_port, const char *expected_path) {
    total_tests++;
    ParsedUrl out;
    memset(&out, 0, sizeof(out));

    ParseStatus status = parse_http_url(url, &out);
    if (status != PARSE_OK) {
        printf("FAIL: '%s' expected PARSE_OK, got %s\n", url, parse_status_to_string(status));
        return;
    }
    if (strcmp(out.host, expected_host) != 0) {
        printf("FAIL: '%s' host expected '%s', got '%s'\n", url, expected_host, out.host);
        return;
    }
    if (out.port != expected_port) {
        printf("FAIL: '%s' port expected %u, got %u\n", url, expected_port, out.port);
        return;
    }
    if (strcmp(out.path, expected_path) != 0) {
        printf("FAIL: '%s' path expected '%s', got '%s'\n", url, expected_path, out.path);
        return;
    }
    passed_tests++;
}

static void test_invalid(const char *url, ParseStatus expected_status) {
    total_tests++;
    ParsedUrl out;
    memset(&out, 0, sizeof(out));

    ParseStatus status = parse_http_url(url, &out);
    if (status != expected_status) {
        printf("FAIL: '%s' expected %s (%d), got %s (%d)\n",
               url ? url : "(null)",
               parse_status_to_string(expected_status), expected_status,
               parse_status_to_string(status), status);
        return;
    }
    passed_tests++;
}


static void test_connect_ok(const char *line, const char *host, uint16_t port) {
    total_tests++;
    ParsedConnect c;
    memset(&c, 0, sizeof(c));
    ParseStatus st = parse_connect_request(line, &c);
    if (st != PARSE_OK) {
        printf("FAIL: CONNECT '%s' expected PARSE_OK, got %s\n", line, parse_status_to_string(st));
        return;
    }
    if (strcmp(c.host, host) != 0 || c.port != port) {
        printf("FAIL: CONNECT '%s' expected %s:%u, got %s:%u\n", line, host, port, c.host, c.port);
        return;
    }
    passed_tests++;
}

static void test_connect_bad(const char *line, ParseStatus expected) {
    total_tests++;
    ParsedConnect c;
    ParseStatus st = parse_connect_request(line, &c);
    if (st != expected) {
        printf("FAIL: CONNECT '%s' expected %s, got %s\n", line ? line : "(null)",
               parse_status_to_string(expected), parse_status_to_string(st));
        return;
    }
    passed_tests++;
}

static void run_connect_tests(void) {
    test_connect_ok("CONNECT example.com:443 HTTP/1.1", "example.com", 443);
    test_connect_ok("CONNECT example.com:443 HTTP/1.0", "example.com", 443);
    test_connect_ok("CONNECT example.com:443", "example.com", 443);
    test_connect_ok("CONNECT EXAMPLE.Com:443 HTTP/1.1", "example.com", 443);
    test_connect_ok("CONNECT sub.example.co.uk:8443 HTTP/1.1", "sub.example.co.uk", 8443);
    test_connect_ok("CONNECT 93.184.216.34:443 HTTP/1.1", "93.184.216.34", 443);
    test_connect_ok("CONNECT a:1 HTTP/1.1", "a", 1);
    test_connect_ok("CONNECT a:65535 HTTP/1.1", "a", 65535);
    test_connect_ok("CONNECT under_score.test:443 HTTP/1.1", "under_score.test", 443);

    test_connect_bad(NULL, PARSE_ERR_MALFORMED);
    test_connect_bad("GET http://example.com/ HTTP/1.1", PARSE_ERR_MALFORMED);
    test_connect_bad("connect example.com:443 HTTP/1.1", PARSE_ERR_MALFORMED); /* method is case-sensitive */
    test_connect_bad("CONNECT", PARSE_ERR_MALFORMED);
    test_connect_bad("CONNECT ", PARSE_ERR_EMPTY_HOST);
    test_connect_bad("CONNECT  example.com:443", PARSE_ERR_EMPTY_HOST);
    test_connect_bad("CONNECT example.com", PARSE_ERR_INVALID_PORT);
    test_connect_bad("CONNECT example.com:", PARSE_ERR_INVALID_PORT);
    test_connect_bad("CONNECT example.com:abc", PARSE_ERR_INVALID_PORT);
    test_connect_bad("CONNECT example.com:0", PARSE_ERR_INVALID_PORT);
    test_connect_bad("CONNECT example.com:65536", PARSE_ERR_INVALID_PORT);
    test_connect_bad("CONNECT example.com:-1", PARSE_ERR_INVALID_PORT);
    test_connect_bad("CONNECT example.com:443x", PARSE_ERR_INVALID_PORT);
    test_connect_bad("CONNECT example.com:0000443", PARSE_ERR_INVALID_PORT);
    test_connect_bad("CONNECT :443", PARSE_ERR_EMPTY_HOST);
    test_connect_bad("CONNECT example.com:443:80", PARSE_ERR_MALFORMED);
    test_connect_bad("CONNECT ::1:443", PARSE_ERR_MALFORMED);
    test_connect_bad("CONNECT [::1]:443", PARSE_ERR_INVALID_HOST);
    test_connect_bad("CONNECT user@example.com:443", PARSE_ERR_CREDENTIALS);
    test_connect_bad("CONNECT user:pw@example.com:443", PARSE_ERR_CREDENTIALS);
    test_connect_bad("CONNECT example.com/path:443", PARSE_ERR_INVALID_HOST);
    test_connect_bad("CONNECT exa mple.com:443", PARSE_ERR_MALFORMED);
    test_connect_bad("CONNECT example.com:443 HTTP/2", PARSE_ERR_MALFORMED);
    test_connect_bad("CONNECT example.com:443 HTTP/1.1 extra", PARSE_ERR_MALFORMED);
    test_connect_bad("CONNECT example.com:443 FTP/1.1", PARSE_ERR_MALFORMED);
    test_connect_bad("CONNECT exam!ple.com:443", PARSE_ERR_INVALID_HOST);
    test_connect_bad("CONNECT example.com:443\r", PARSE_ERR_CONTROL_CHAR);
    test_connect_bad("CONNECT exa\tmple.com:443", PARSE_ERR_CONTROL_CHAR);

    char long_host[400];
    strcpy(long_host, "CONNECT ");
    memset(long_host + 8, 'a', 300);
    strcpy(long_host + 308, ":443");
    test_connect_bad(long_host, PARSE_ERR_HOST_TOO_LONG);

    static char huge[MAX_URL_LEN + 64];
    strcpy(huge, "CONNECT ");
    memset(huge + 8, 'a', sizeof(huge) - 9);
    huge[sizeof(huge) - 1] = '\0';
    test_connect_bad(huge, PARSE_ERR_OVERLONG);

    total_tests++;
    if (request_is_connect("CONNECT x:1") && !request_is_connect("CONNECTX") && !request_is_connect("GET") &&
        !request_is_connect(NULL)) {
        passed_tests++;
    } else {
        printf("FAIL: request_is_connect misclassified an input\n");
    }
}

int main(void) {
    printf("=== Running URL Parser Unit Tests ===\n");

    /* Valid test cases */
    test_valid("http://example.com/index.html", "example.com", 80, "/index.html");
    test_valid("http://example.com", "example.com", 80, "/");
    test_valid("http://example.com/", "example.com", 80, "/");
    test_valid("http://example.com:8080/api/v1", "example.com", 8080, "/api/v1");
    test_valid("http://example.com:8080", "example.com", 8080, "/");
    test_valid("HTTP://EXAMPLE.COM/PATH", "example.com", 80, "/PATH");
    test_valid("http://ExAmPLe.CoM:443/", "example.com", 443, "/");
    test_valid("http://example.com/search?q=test&page=1", "example.com", 80, "/search?q=test&page=1");
    test_valid("http://example.com?direct_query=true", "example.com", 80, "/?direct_query=true");
    test_valid("http://192.168.1.1:3000/status", "192.168.1.1", 3000, "/status");
    test_valid("http://sub.sub2.domain.org/nested/dir/", "sub.sub2.domain.org", 80, "/nested/dir/");
    test_valid("http://example.com:65535/max-port", "example.com", 65535, "/max-port");
    test_valid("http://example.com:1/min-port", "example.com", 1, "/min-port");

    /* Invalid test cases */
    test_invalid(NULL, PARSE_ERR_MALFORMED);
    test_invalid("", PARSE_ERR_MALFORMED);
    test_invalid("https://example.com/", PARSE_ERR_INVALID_SCHEME);
    test_invalid("ftp://example.com/", PARSE_ERR_INVALID_SCHEME);
    test_invalid("example.com/index.html", PARSE_ERR_INVALID_SCHEME);
    test_invalid("http:/example.com", PARSE_ERR_INVALID_SCHEME);
    test_invalid("http://user:pass@example.com/", PARSE_ERR_CREDENTIALS);
    test_invalid("http://admin@example.com/resource", PARSE_ERR_CREDENTIALS);
    test_invalid("http:///index.html", PARSE_ERR_EMPTY_HOST);
    test_invalid("http://:8080/path", PARSE_ERR_EMPTY_HOST);
    test_invalid("http://example.com:/path", PARSE_ERR_INVALID_PORT);
    test_invalid("http://example.com:abc/", PARSE_ERR_INVALID_PORT);
    test_invalid("http://example.com:0/", PARSE_ERR_INVALID_PORT);
    test_invalid("http://example.com:65536/", PARSE_ERR_INVALID_PORT);
    test_invalid("http://example.com/index.html#section", PARSE_ERR_FRAGMENT);
    test_invalid("http://example.com/newline\n", PARSE_ERR_CONTROL_CHAR);
    test_invalid("http://example.com/spaced path", PARSE_ERR_CONTROL_CHAR);

    /* Test host exceeding 256 bytes buffer */
    char long_host_url[300];
    snprintf(long_host_url, sizeof(long_host_url), "http://%s/",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    test_invalid(long_host_url, PARSE_ERR_HOST_TOO_LONG);

    run_connect_tests();

    printf("Result: %d / %d tests passed successfully.\n", passed_tests, total_tests);
    return (passed_tests == total_tests) ? 0 : 1;
}