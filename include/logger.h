#pragma once
/* logger.h: Declares the privacy-aware structured logging functions used to record proxy decisions without leaking sensitive data. */

#include <stddef.h>

/* Size of the buffer logger_sanitize_host() needs for its largest possible output. */
#define LOG_HOST_MAX 256

/*
 * Opens (creating if needed) an append-only log file with owner-only
 * permissions. Returns 0 on success, -1 on failure. A failure is NOT
 * fatal: logging simply stays disabled and every later logger call
 * becomes a harmless no-op, so a bad log path can never stop the proxy
 * from serving traffic. Call once, before any worker threads start.
 */
int logger_init(const char *path);

/* Closes the log file. Safe to call even if logger_init() failed. */
void logger_close(void);

/* Returns 1 if a log file is currently open, 0 otherwise. */
int logger_is_enabled(void);

/* Returns a process-unique, increasing request ID. Thread-safe. */
unsigned long logger_next_request_id(void);

/*
 * Reduces `in` to a value that is safe to write to a log line:
 *   - drops a leading "scheme://",
 *   - cuts everything from the first '/', '?' or '#' (path, query, fragment),
 *   - drops "user:password@" credentials,
 *   - lowercases, and replaces anything outside [a-z0-9.-_:[]] with '_'
 *     (so newlines/spaces can never forge extra log lines),
 *   - returns "-" for NULL/empty input.
 * `out` is always NUL-terminated (out_len must be > 0).
 */
void logger_sanitize_host(const char *in, char *out, size_t out_len);

/*
 * Appends one structured line:
 *   <UTC timestamp> req=<id> host=<host> decision=<word> status=<http>
 *   bytes=<forwarded> duration_ms=<n>
 * `host` is run through logger_sanitize_host() and `decision` is reduced
 * to [a-z0-9_], so callers cannot leak a URL's secrets or break the
 * one-line-per-request format. The whole line is written with a single
 * write() while holding a mutex, so concurrent requests never interleave.
 * Never terminates the process; write failures are only counted.
 */
void log_request(unsigned long request_id, const char *host, const char *decision, int status,
                 unsigned long long bytes_forwarded, long duration_ms);

/* Number of log lines that could not be written (disk full, closed fd, ...). */
unsigned long logger_failure_count(void);
