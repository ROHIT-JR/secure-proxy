/* logger.c: Implements a mutex-protected append-only log writer that strips credentials, query strings, and fragments before writing. */

#define _POSIX_C_SOURCE 200809L

#include "logger.h"
#include "util.h"

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LOG_LINE_MAX 512
#define LOG_DECISION_MAX 32

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_log_fd = -1;           /* protected by g_log_mutex */
static unsigned long g_failures = 0; /* protected by g_log_mutex */
static atomic_ulong g_next_request_id = 1;

int logger_init(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return -1;
    }

    /* O_APPEND makes every write() land at the current end of file, even if
     * another process (e.g. logrotate's copytruncate) touches the file.
     * 0600: request metadata is private to the user running the proxy. */
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }

    pthread_mutex_lock(&g_log_mutex);
    if (g_log_fd >= 0) {
        close(g_log_fd);
    }
    g_log_fd = fd;
    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}

void logger_close(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_fd >= 0) {
        close(g_log_fd);
        g_log_fd = -1;
    }
    pthread_mutex_unlock(&g_log_mutex);
}

int logger_is_enabled(void) {
    pthread_mutex_lock(&g_log_mutex);
    int enabled = (g_log_fd >= 0);
    pthread_mutex_unlock(&g_log_mutex);
    return enabled;
}

unsigned long logger_next_request_id(void) {
    return atomic_fetch_add(&g_next_request_id, 1);
}

unsigned long logger_failure_count(void) {
    pthread_mutex_lock(&g_log_mutex);
    unsigned long n = g_failures;
    pthread_mutex_unlock(&g_log_mutex);
    return n;
}

void logger_sanitize_host(const char *in, char *out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (in == NULL) {
        snprintf(out, out_len, "-");
        return;
    }

    /* 1. Drop a leading "scheme://". */
    const char *p = strstr(in, "://");
    p = (p != NULL) ? p + 3 : in;

    /* 2. Authority only: stop at the first path / query / fragment delimiter. */
    size_t auth_len = strcspn(p, "/?#");

    /* 3. Drop "user:password@" -- everything up to the LAST '@' in the authority. */
    size_t start = 0;
    for (size_t i = 0; i < auth_len; i++) {
        if (p[i] == '@') {
            start = i + 1;
        }
    }

    /* 4. Lowercase and replace anything that isn't a plain host character. */
    size_t o = 0;
    for (size_t i = start; i < auth_len && o + 1 < out_len; i++) {
        unsigned char c = (unsigned char)p[i];
        if (isalnum(c)) {
            out[o++] = (char)tolower(c);
        } else if (c == '.' || c == '-' || c == '_' || c == ':' || c == '[' || c == ']') {
            out[o++] = (char)c;
        } else {
            out[o++] = '_';
        }
    }
    out[o] = '\0';

    if (o == 0) {
        snprintf(out, out_len, "-");
    }
}

/* Reduces a caller-supplied decision word to [a-z0-9_] so it cannot inject spaces/newlines. */
static void sanitize_decision(const char *in, char *out, size_t out_len) {
    size_t o = 0;
    if (in != NULL) {
        for (size_t i = 0; in[i] != '\0' && o + 1 < out_len; i++) {
            unsigned char c = (unsigned char)in[i];
            out[o++] = isalnum(c) ? (char)tolower(c) : '_';
        }
    }
    if (o == 0 && out_len > 1) {
        out[o++] = '-';
    }
    out[o] = '\0';
}

void log_request(unsigned long request_id, const char *host, const char *decision, int status,
                 unsigned long long bytes_forwarded, long duration_ms) {
    /* Cheap early exit when logging is disabled; re-checked under the lock below. */
    if (!logger_is_enabled()) {
        return;
    }

    char safe_host[LOG_HOST_MAX];
    char safe_decision[LOG_DECISION_MAX];
    logger_sanitize_host(host, safe_host, sizeof(safe_host));
    sanitize_decision(decision, safe_decision, sizeof(safe_decision));

    char timestamp[32];
    time_t now = time(NULL);
    struct tm tm_utc;
    if (gmtime_r(&now, &tm_utc) == NULL ||
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {
        snprintf(timestamp, sizeof(timestamp), "-");
    }

    /* Build the complete line first so it can go out in ONE write(). */
    char line[LOG_LINE_MAX];
    int len = snprintf(line, sizeof(line),
                       "%s req=%lu host=%s decision=%s status=%d bytes=%llu duration_ms=%ld\n",
                       timestamp, request_id, safe_host, safe_decision, status, bytes_forwarded,
                       duration_ms);
    if (len < 0) {
        return;
    }
    if ((size_t)len >= sizeof(line)) { /* truncated: keep it a single, newline-terminated line */
        len = (int)sizeof(line) - 1;
        line[len - 1] = '\n';
    }

    pthread_mutex_lock(&g_log_mutex);
    if (g_log_fd >= 0 && send_all(g_log_fd, line, (size_t)len) != (ssize_t)len) {
        g_failures++; /* disk full, fd closed, ... -- count it, never abort */
    }
    pthread_mutex_unlock(&g_log_mutex);
}
