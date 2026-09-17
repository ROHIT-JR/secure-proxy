/* test_parser.c: Unit tests for safe URL parsing and domain normalisation. */
#include "request_parser.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

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

int main(void) {
    printf("=== Running URL Parser Unit Tests ===\n");

    /* 1-13: Valid test cases */
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

    /* 14-30: Invalid test cases */
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

    printf("Result: %d / %d tests passed successfully.\n", passed_tests, total_tests);
    return (passed_tests == total_tests) ? 0 : 1;
}