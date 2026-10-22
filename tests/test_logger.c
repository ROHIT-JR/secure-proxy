/* test_logger.c: Unit tests for the privacy-aware request logger (sanitising, concurrency, failure handling). */

#define _POSIX_C_SOURCE 200809L

#include "logger.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int total_tests = 0;
static int passed_tests = 0;

#define CHECK(cond, ...)                                      \
    do {                                                      \
        total_tests++;                                        \
        if (cond) {                                           \
            passed_tests++;                                   \
        } else {                                              \
            printf("FAIL (line %d): ", __LINE__);             \
            printf(__VA_ARGS__);                              \
            printf("\n");                                     \
        }                                                     \
    } while (0)

static void expect_sanitized(const char *in, const char *expected) {
    char out[LOG_HOST_MAX];
    logger_sanitize_host(in, out, sizeof(out));
    CHECK(strcmp(out, expected) == 0, "sanitize(\"%s\") expected \"%s\", got \"%s\"",
          in ? in : "(null)", expected, out);
}

static void test_sanitize_host(void) {
    expect_sanitized("example.com", "example.com");
    expect_sanitized("EXAMPLE.Com", "example.com");
    expect_sanitized("sub.example.com:8080", "sub.example.com:8080");
    expect_sanitized("[::1]", "[::1]");
    expect_sanitized(NULL, "-");
    expect_sanitized("", "-");

    /* The privacy requirements: credentials, query strings, fragments, paths are all dropped. */
    expect_sanitized("http://example.com/path?token=secret", "example.com");
    expect_sanitized("http://example.com?token=secret", "example.com");
    expect_sanitized("http://example.com/page#frag", "example.com");
    expect_sanitized("http://user:hunter2@example.com/", "example.com");
    expect_sanitized("user:hunter2@example.com", "example.com");
    expect_sanitized("http://a@b@example.com/", "example.com");
    expect_sanitized("http://user:pw@example.com:81/x?y=z#w", "example.com:81");

    /* Log-injection attempts must not be able to create extra lines or fields. */
    expect_sanitized("evil.com\nFAKE LINE", "evil.com_fake_line");
    expect_sanitized("evil.com decision=allowed", "evil.com_decision_allowed");
    expect_sanitized("a\r\nb", "a__b");

    /* Output is bounded and always NUL-terminated, even for hostile input sizes. */
    char big[1000];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char small[16];
    logger_sanitize_host(big, small, sizeof(small));
    CHECK(strlen(small) == sizeof(small) - 1, "truncates to buffer size, got len %zu", strlen(small));
}

/* ---------- concurrent writes ---------- */

#define THREADS 8
#define LINES_PER_THREAD 250

static void *writer_thread(void *arg) {
    unsigned long t = (unsigned long)(size_t)arg;
    for (unsigned long i = 0; i < LINES_PER_THREAD; i++) {
        /* Encode (thread, sequence) in the request id so every line is identifiable. */
        log_request(t * 100000UL + i, "example.com", "allowed", 200, 1234, 5);
    }
    return NULL;
}

static void make_temp_path(char *path, size_t len) {
    snprintf(path, len, "/tmp/test_logger_XXXXXX");
    int fd = mkstemp(path);
    if (fd >= 0) {
        close(fd);
    }
}

static void test_concurrent_lines_not_interleaved(void) {
    char path[64];
    make_temp_path(path, sizeof(path));
    CHECK(logger_init(path) == 0, "logger_init on a temp file should succeed");
    CHECK(logger_is_enabled() == 1, "logger should report enabled after init");

    pthread_t threads[THREADS];
    for (size_t t = 0; t < THREADS; t++) {
        pthread_create(&threads[t], NULL, writer_thread, (void *)t);
    }
    for (size_t t = 0; t < THREADS; t++) {
        pthread_join(threads[t], NULL);
    }
    logger_close();

    static unsigned char seen[THREADS][LINES_PER_THREAD];
    memset(seen, 0, sizeof(seen));

    FILE *f = fopen(path, "r");
    CHECK(f != NULL, "could not reopen the log file");
    int lines = 0, malformed = 0, duplicates = 0;
    char line[1024];
    while (f != NULL && fgets(line, sizeof(line), f) != NULL) {
        lines++;
        char ts[40], host[LOG_HOST_MAX], decision[40];
        unsigned long id;
        int status;
        unsigned long long bytes;
        long dur;
        int n = sscanf(line, "%39s req=%lu host=%255s decision=%39s status=%d bytes=%llu duration_ms=%ld",
                       ts, &id, host, decision, &status, &bytes, &dur);
        size_t len = strlen(line);
        if (n != 7 || line[len - 1] != '\n' ||
            strcmp(host, "example.com") != 0 || strcmp(decision, "allowed") != 0 || status != 200 ||
            bytes != 1234 || dur != 5 || id / 100000UL >= THREADS || id % 100000UL >= LINES_PER_THREAD) {
            malformed++;
            continue;
        }
        if (seen[id / 100000UL][id % 100000UL]++) {
            duplicates++;
        }
    }
    if (f != NULL) {
        fclose(f);
    }
    unlink(path);

    CHECK(lines == THREADS * LINES_PER_THREAD, "expected %d lines, got %d", THREADS * LINES_PER_THREAD,
          lines);
    CHECK(malformed == 0, "%d malformed/interleaved lines", malformed);
    CHECK(duplicates == 0, "%d duplicate lines", duplicates);
}

static void test_timestamp_and_format(void) {
    char path[64];
    make_temp_path(path, sizeof(path));
    logger_init(path);
    log_request(42, "Example.COM", "bad_request", 400, 0, 0);
    logger_close();

    FILE *f = fopen(path, "r");
    char line[512] = "";
    if (f != NULL) {
        if (fgets(line, sizeof(line), f) == NULL) {
            line[0] = '\0';
        }
        fclose(f);
    }
    unlink(path);

    int y, mo, d, h, mi, s;
    char rest[256];
    int n = sscanf(line, "%4d-%2d-%2dT%2d:%2d:%2dZ %255[^\n]", &y, &mo, &d, &h, &mi, &s, rest);
    CHECK(n == 7, "line should start with an ISO-8601 UTC timestamp: \"%s\"", line);
    CHECK(strcmp(rest, "req=42 host=example.com decision=bad_request status=400 bytes=0 duration_ms=0") == 0,
          "unexpected fields: \"%s\"", rest);
}

static void test_privacy_never_logs_secrets(void) {
    char path[64];
    make_temp_path(path, sizeof(path));
    logger_init(path);
    /* Even if a caller mistakenly hands over a full URL, nothing sensitive may reach the file. */
    log_request(1, "http://admin:hunter2@example.com/login?token=secret&session=abc#frag", "allowed",
                200, 10, 1);
    log_request(2, "example.com", "allowed\nforged=1", 200, 10, 1);
    logger_close();

    FILE *f = fopen(path, "r");
    char contents[2048] = "";
    size_t got = f ? fread(contents, 1, sizeof(contents) - 1, f) : 0;
    contents[got] = '\0';
    if (f != NULL) {
        fclose(f);
    }
    unlink(path);

    CHECK(strstr(contents, "secret") == NULL, "query value leaked into the log");
    CHECK(strstr(contents, "token") == NULL, "query key leaked into the log");
    CHECK(strstr(contents, "hunter2") == NULL, "password leaked into the log");
    CHECK(strstr(contents, "admin") == NULL, "username leaked into the log");
    CHECK(strstr(contents, "session") == NULL, "query key leaked into the log");
    CHECK(strstr(contents, "frag") == NULL, "fragment leaked into the log");
    CHECK(strstr(contents, "login") == NULL, "path leaked into the log");
    CHECK(strstr(contents, "host=example.com") != NULL, "host should still be logged");

    int newlines = 0;
    for (const char *p = contents; *p; p++) {
        newlines += (*p == '\n');
    }
    CHECK(newlines == 2, "two log calls must yield exactly two lines, got %d", newlines);
}

static void test_failures_are_not_fatal(void) {
    /* 1. Unopenable path: init fails, later calls are harmless no-ops. */
    CHECK(logger_init("/nonexistent-dir/definitely/not/here.log") == -1, "init on a bad path should fail");
    CHECK(logger_init(NULL) == -1, "init(NULL) should fail");
    CHECK(logger_init("") == -1, "init(\"\") should fail");
    CHECK(logger_is_enabled() == 0, "logging should be disabled after a failed init");
    log_request(1, "example.com", "allowed", 200, 1, 1); /* must not crash */
    CHECK(1, "log_request after a failed init did not crash");

    /* 2. A real write failure: /dev/full opens fine but every write() returns ENOSPC. */
    if (access("/dev/full", W_OK) == 0) {
        unsigned long before = logger_failure_count();
        CHECK(logger_init("/dev/full") == 0, "/dev/full should open");
        log_request(2, "example.com", "allowed", 200, 1, 1);
        log_request(3, "example.com", "allowed", 200, 1, 1);
        CHECK(logger_failure_count() == before + 2, "write failures should be counted, got %lu",
              logger_failure_count() - before);
        logger_close();
    }

    /* 3. Safe to close repeatedly / when never opened. */
    logger_close();
    logger_close();
    CHECK(1, "repeated logger_close() did not crash");
}

static void test_extras_field(void) {
    char path[64];
    make_temp_path(path, sizeof(path));
    logger_init(path);
    log_request_ex(5, "example.com", "allowed", 200, 9, 1, "cache=hit");
    log_request_ex(6, "example.com", "allowed", 200, 9, 1, NULL);
    log_request_ex(7, "example.com", "allowed", 200, 9, 1, "");
    /* hostile extras: injection and URL material must be neutralised */
    log_request_ex(8, "example.com", "allowed", 200, 9, 1, "cache=hit\nFORGED line http://u:p@x/?token=secret");
    logger_close();

    FILE *f = fopen(path, "r");
    char l1[512] = "", l2[512] = "", l3[512] = "", l4[512] = "", l5[512] = "";
    if (f != NULL) {
        if (!fgets(l1, sizeof(l1), f)) l1[0] = 0;
        if (!fgets(l2, sizeof(l2), f)) l2[0] = 0;
        if (!fgets(l3, sizeof(l3), f)) l3[0] = 0;
        if (!fgets(l4, sizeof(l4), f)) l4[0] = 0;
        if (!fgets(l5, sizeof(l5), f)) l5[0] = 0;
        fclose(f);
    }
    unlink(path);
    CHECK(strstr(l1, "duration_ms=1 cache=hit\n") != NULL, "extras appended: %s", l1);
    CHECK(strstr(l2, "duration_ms=1\n") != NULL && strstr(l2, "cache") == NULL, "NULL extras add nothing: %s", l2);
    CHECK(strstr(l3, "duration_ms=1\n") != NULL, "empty extras add nothing: %s", l3);
    CHECK(l5[0] == '\0', "an injected newline must not create a 5th line");
    CHECK(strstr(l4, "://") == NULL && strchr(l4, '?') == NULL && strchr(l4, '@') == NULL,
          "no URL structure survives in extras (the logger cannot judge letters, so callers must only pass fixed tokens): %s", l4);
}

static void test_request_ids_unique_and_increasing(void) {
    unsigned long a = logger_next_request_id();
    unsigned long b = logger_next_request_id();
    unsigned long c = logger_next_request_id();
    CHECK(a < b && b < c, "request ids must strictly increase (%lu %lu %lu)", a, b, c);
}

int main(void) {
    printf("=== Running Logger Unit Tests ===\n");
    test_sanitize_host();
    test_timestamp_and_format();
    test_privacy_never_logs_secrets();
    test_concurrent_lines_not_interleaved();
    test_failures_are_not_fatal();
    test_request_ids_unique_and_increasing();
    test_extras_field();
    printf("Result: %d / %d tests passed successfully.\n", passed_tests, total_tests);
    return passed_tests == total_tests ? 0 : 1;
}
