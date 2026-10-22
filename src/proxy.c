#define _DEFAULT_SOURCE
/* proxy.c: Program entry point that starts the listening socket and dispatches accepted connections to worker threads. */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "cache.h"
#include "decision.h"
#include "logger.h"
#include "origin_client.h"
#include "policy.h"
#include "reputation.h"
#include "request_parser.h"
#include "util.h"

#define LISTEN_PORT 8080
#define REQUEST_LINE_BUF_LEN (MAX_URL_LEN + 3) /* URL + '\r' + '\n' + '\0' */
#define CLIENT_READ_TIMEOUT_SECONDS 5
#define MAX_CONCURRENT_CLIENTS 64
#define DEFAULT_LOG_PATH "proxy.log"
#define CONNECT_DEFAULT_PORT 443          /* the only port CONNECT may reach unless overridden */
#define CONNECT_HEADER_MAX 8192           /* bound on the headers that follow a CONNECT line */
#define TUNNEL_DEFAULT_IDLE_SECONDS 120   /* an idle tunnel is closed after this long */
#define TUNNEL_HALF_CLOSE_SECONDS 5       /* grace once one side has finished and closed */
#define TUNNEL_BUF_LEN 16384
#define TUNNEL_SEND_TIMEOUT_SECONDS 30
#define DEFAULT_ALLOWLIST_PATH "config/allowlist.txt"
#define DEFAULT_BLOCKLIST_PATH "config/blocklist.txt"

/* Heap-allocated per-connection arguments passed to worker threads */
typedef struct {
    int client_fd;
} ClientArgs;

/* Allowlist/blocklist rules: loaded once at startup, then only read by worker threads. */
static Policy g_policy;

/* Optional extra "key=value" fields for the request log line. Only fixed tokens go in. */
typedef struct {
    char text[96];
} LogExtras;

static void extras_add(LogExtras *e, const char *token) {
    size_t used = strlen(e->text);
    size_t need = strlen(token) + (used > 0 ? 1 : 0);
    if (used + need + 1 > sizeof(e->text)) {
        return; /* never truncate a token in half */
    }
    if (used > 0) {
        e->text[used++] = ' ';
    }
    memcpy(e->text + used, token, strlen(token) + 1);
}

static unsigned g_connect_port = CONNECT_DEFAULT_PORT;
static int g_tunnel_idle_seconds = TUNNEL_DEFAULT_IDLE_SECONDS;

/* Concurrency tracking state */
static pthread_mutex_t g_active_clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_active_clients = 0;

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

/* Shuts down the write side, drains and discards any input the client
 * already sent but that we never read (e.g. the tail of an oversized
 * request line), then closes the socket.
 *
 * This matters because closing a socket while unread bytes are still
 * sitting in its kernel receive buffer makes the OS send a TCP RST
 * instead of an orderly FIN. A RST can arrive before the client has
 * finished reading the response we just sent, truncating it -- the
 * client would see "connection reset" instead of our actual error page.
 * Draining first (bounded by a short timeout, since a well-behaved
 * client won't have much more queued) avoids that race entirely. */
static void drain_and_close(int client_fd) {
    shutdown(client_fd, SHUT_WR);

    struct timeval drain_timeout;
    drain_timeout.tv_sec = 0;
    drain_timeout.tv_usec = 200000; /* 200ms is ample for data already in flight */
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &drain_timeout, sizeof(drain_timeout));

    char discard[512];
    while (recv(client_fd, discard, sizeof(discard), 0) > 0) {
        /* discard */
    }

    close(client_fd);
}

/* The log "decision" word for each blocking reason. */
static const char *blocked_label(DecisionReason r) {
    switch (r) {
        case REASON_POLICY: return "blocked_policy";
        case REASON_NETWORK: return "blocked_private";
        case REASON_REPUTATION: return "blocked_reputation";
        case REASON_PORT: return "blocked_port";
        case REASON_NONE: break;
    }
    return "blocked";
}

/* Sends the HTML block page: the request ID and a safe reason category, nothing else.
 * The technical detail (which rule, address, or provider answer) is only in the server log. */
static void send_block_page(int client_fd, unsigned long request_id, DecisionReason reason) {
    char page[2048];
    size_t n = decision_build_block_response(page, sizeof(page), request_id, reason);
    if (n > 0) {
        send_all(client_fd, page, n);
    }
}

/* The single decision point for "may we talk to this destination at all?", shared by
 * plain HTTP requests and CONNECT tunnels so both obey exactly the same rules.
 *
 * It gathers the policy and reputation signals into `sig` and returns the combined, documented
 * decision (see docs/risk-scoring.md). Later stages (network safety, tunnel port) add their own
 * signals to the same `sig` and call decision_evaluate() again. */
static Decision check_destination(const char *host, DecisionInputs *sig, LogExtras *extras) {
    if (policy_check_host(&g_policy, host) != POLICY_ALLOW) {
        sig->policy_denied = 1;
        return decision_evaluate(sig);
    }

    /* Reputation: ask only about real hostnames. IP addresses and local names are never sent
     * to a provider (there is nothing useful to learn, and they are handled by the network-safety
     * checks). Only the bare hostname leaves this function. */
    if (reputation_is_enabled() && !hostname_is_local_name(host) && !host_is_numeric_address(host)) {
        ReputationResult r = reputation_check(host);
        sig->reputation_checked = 1;
        sig->reputation = r.verdict;
        char token[48];
        snprintf(token, sizeof(token), "rep=%s", reputation_verdict_name(r.verdict));
        extras_add(extras, token);
        if (r.verdict == REP_UNAVAILABLE) {
            /* An observable event, NOT an assumption that the host is malicious: the request
             * continues, and the reason is logged so an outage is visible. */
            snprintf(token, sizeof(token), "rep_reason=%s", reputation_reason_name(r.reason));
            extras_add(extras, token);
        }
    }
    return decision_evaluate(sig);
}

/* Reads and discards the header lines that follow a CONNECT line, up to the blank line.
 * Stops exactly at the blank line, so nothing the client sends afterwards (such as a
 * TLS ClientHello sent early) is consumed -- it stays queued and is relayed untouched. */
static ReadLineStatus consume_request_headers(int fd) {
    size_t total = 0, line_len = 0;
    for (;;) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
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
        if (++total > CONNECT_HEADER_MAX) {
            return LINE_TOO_LARGE;
        }
        if (c == '\n') {
            if (line_len == 0) {
                return LINE_OK; /* blank line: end of the headers */
            }
            line_len = 0;
        } else if (c != '\r') {
            line_len++;
        }
    }
}

/* Copies bytes in both directions between `a` (client) and `b` (origin) until both
 * directions are finished or the tunnel is idle. The bytes are NEVER examined, stored
 * or logged -- this is a blind relay, which is what keeps TLS end to end.
 *
 * When one side finishes (EOF or error) its peer gets a write-shutdown so it learns
 * the stream ended, and the other direction keeps flowing until it also finishes or
 * stays idle for TUNNEL_HALF_CLOSE_SECONDS. Returns the number of bytes relayed. */
static unsigned long long relay_tunnel(int a, int b, int idle_seconds) {
    unsigned long long total = 0;
    int open_dir[2] = {1, 1}; /* [0] = a->b still open, [1] = b->a still open */
    int fds[2] = {a, b};
    int timeout_ms = idle_seconds * 1000;
    char buf[TUNNEL_BUF_LEN];

    while (open_dir[0] || open_dir[1]) {
        struct pollfd pfd[2];
        for (int i = 0; i < 2; i++) {
            pfd[i].fd = open_dir[i] ? fds[i] : -1; /* a negative fd is ignored by poll() */
            pfd[i].events = POLLIN;
            pfd[i].revents = 0;
        }
        int rc = poll(pfd, 2, timeout_ms);
        if (rc == 0) {
            break; /* idle for too long */
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < 2; i++) {
            if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR))) {
                continue;
            }
            int src = fds[i], dst = fds[1 - i];
            ssize_t n = recv(src, buf, sizeof(buf), 0);
            if (n > 0) {
                if (send_all(dst, buf, (size_t)n) < 0) {
                    return total; /* the receiving side is gone */
                }
                total += (unsigned long long)n;
            } else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                shutdown(dst, SHUT_WR); /* tell the peer this direction is finished */
                open_dir[i] = 0;
                if (timeout_ms > TUNNEL_HALF_CLOSE_SECONDS * 1000) {
                    timeout_ms = TUNNEL_HALF_CLOSE_SECONDS * 1000;
                }
            }
        }
    }
    return total;
}

/* Result of handling a CONNECT request, for the caller's log line. */
typedef struct {
    const char *decision;
    int status;
    unsigned long long bytes;
    char host[MAX_HOST_LEN]; /* validated host, or "-" */
} ConnectOutcome;

/* Handles one CONNECT request end to end. `line` has its CR/LF removed. The caller closes
 * client_fd. HTTPS is only ever tunnelled: no TLS termination, no certificates, no inspection. */
static void handle_connect(int client_fd, unsigned long request_id, const char *line, ConnectOutcome *out,
                           LogExtras *extras, DecisionInputs *sig, int *risk_known) {
    snprintf(out->host, sizeof(out->host), "-");
    out->decision = "bad_request";
    out->status = 400;
    out->bytes = 0;

    ParsedConnect target;
    ParseStatus ps = parse_connect_request(line, &target);
    if (ps != PARSE_OK) {
        char body[256];
        snprintf(body, sizeof(body), "400 Bad Request: %s\n", parse_status_to_string(ps));
        send_error_response(client_fd, 400, "Bad Request", body);
        return;
    }
    snprintf(out->host, sizeof(out->host), "%s", target.host);

    ReadLineStatus hs = consume_request_headers(client_fd);
    if (hs == LINE_TIMEOUT) {
        send_error_response(client_fd, 408, "Request Timeout", "408 Request Timeout: CONNECT headers incomplete.\n");
        out->decision = "timeout";
        out->status = 408;
        return;
    }
    if (hs == LINE_TOO_LARGE) {
        send_error_response(client_fd, 400, "Bad Request", "400 Bad Request: CONNECT headers too large.\n");
        return;
    }
    if (hs != LINE_OK) {
        out->decision = "client_closed";
        out->status = 0;
        return;
    }

    /* Only the HTTPS port: CONNECT must not become a way to reach arbitrary services. */
    *risk_known = 1;
    if (target.port != g_connect_port) {
        sig->port_denied = 1;
        Decision d = decision_evaluate(sig);
        send_block_page(client_fd, request_id, d.reason);
        out->decision = blocked_label(d.reason);
        out->status = 403;
        return;
    }

    Decision d = check_destination(target.host, sig, extras);
    if (d.action == DECISION_BLOCK) {
        send_block_page(client_fd, request_id, d.reason);
        out->decision = blocked_label(d.reason);
        out->status = 403;
        return;
    }

    /* Same safe connect as plain HTTP: local names, private/loopback/link-local addresses and
     * DNS answers are all checked BEFORE the tunnel is created. */
    int origin_fd = -1;
    FetchStatus conn = origin_connect(target.host, target.port, &origin_fd);
    if (conn == FETCH_ERR_UNSAFE_ADDRESS) {
        sig->network_unsafe = 1;
        d = decision_evaluate(sig);
        send_block_page(client_fd, request_id, d.reason);
        out->decision = blocked_label(d.reason);
        out->status = 403;
        return;
    }
    if (conn != FETCH_OK) {
        char body[256];
        snprintf(body, sizeof(body), "502 Bad Gateway: %s\n", fetch_status_to_string(conn));
        send_error_response(client_fd, 502, "Bad Gateway", body);
        out->decision = "bad_gateway";
        out->status = 502;
        return;
    }

    struct timeval send_to = {TUNNEL_SEND_TIMEOUT_SECONDS, 0};
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &send_to, sizeof(send_to));
    setsockopt(origin_fd, SOL_SOCKET, SO_SNDTIMEO, &send_to, sizeof(send_to));

    static const char established[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (send_all(client_fd, established, sizeof(established) - 1) < 0) {
        close(origin_fd);
        out->decision = "client_closed";
        out->status = 0;
        return;
    }

    out->decision = "allowed";
    out->status = 200;
    out->bytes = relay_tunnel(client_fd, origin_fd, g_tunnel_idle_seconds);
    close(origin_fd); /* the single close of the origin socket on every path through here */
}

/* Worker thread entry point: extracts client socket, frees heap arguments,
 * detaches thread, handles the request end-to-end, closes the socket, and
 * decrements the active concurrency count. */
static void *handle_client(void *arg) {
    ClientArgs *args = (ClientArgs *)arg;
    if (args == NULL) {
        pthread_mutex_lock(&g_active_clients_mutex);
        g_active_clients--;
        pthread_mutex_unlock(&g_active_clients_mutex);
        return NULL;
    }

    int client_fd = args->client_fd;
    free(args);

    pthread_detach(pthread_self());

    /* Everything that goes into the request log is collected here and written
     * once, at cleanup. Only the validated, normalised host is ever recorded --
     * never the path, query string, credentials, fragment, or the raw line. */
    unsigned long request_id = logger_next_request_id();
    struct timespec start_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    const char *log_host = "-";
    const char *log_decision = "client_closed";
    int log_status = 0;
    unsigned long long log_bytes = 0;
    LogExtras extras;
    memset(&extras, 0, sizeof(extras));
    const char *cache_state = NULL; /* "cache=hit|miss|stored|bypass", added to the log once at the end */
    FetchStats stats;
    memset(&stats, 0, sizeof(stats));
    ConnectOutcome connect_outcome; /* function scope: log_host may point into it until cleanup */
    DecisionInputs sig;             /* every signal gathered about this request, for the risk score */
    memset(&sig, 0, sizeof(sig));
    int risk_known = 0;             /* 1 once the destination checks have run */

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
            log_decision = "too_large";
            log_status = 413;
            goto cleanup;
        case LINE_TIMEOUT:
            send_error_response(client_fd, 408, "Request Timeout",
                                "408 Request Timeout: No complete request line received.\n");
            log_decision = "timeout";
            log_status = 408;
            goto cleanup;
        case LINE_CLOSED:
        case LINE_ERROR:
            /* Client disconnected or the socket errored; nothing to reply to. */
            goto cleanup;
        case LINE_OK:
            break;
    }

    /* Strip the trailing "\r\n" or "\n" before handing the line to the parser. */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }

    if (request_is_connect(line)) {
        extras_add(&extras, "method=connect");
        handle_connect(client_fd, request_id, line, &connect_outcome, &extras, &sig, &risk_known);
        log_host = connect_outcome.host;
        log_decision = connect_outcome.decision;
        log_status = connect_outcome.status;
        log_bytes = connect_outcome.bytes;
        goto cleanup;
    }

    ParsedUrl parsed;
    ParseStatus parse_status = parse_http_url(line, &parsed);

    if (parse_status != PARSE_OK) {
        char body[256];
        snprintf(body, sizeof(body), "400 Bad Request: %s\n", parse_status_to_string(parse_status));
        send_error_response(client_fd, 400, "Bad Request", body);
        log_decision = "bad_request";
        log_status = 400;
        goto cleanup;
    }

    log_host = parsed.host; /* validated + lowercased by the parser */

    /* Policy is applied BEFORE any DNS lookup or outbound connection, so a
     * blocked destination is never even resolved. */
    risk_known = 1;
    Decision dest = check_destination(parsed.host, &sig, &extras);
    if (dest.action == DECISION_BLOCK) {
        send_block_page(client_fd, request_id, dest.reason);
        log_decision = blocked_label(dest.reason);
        log_status = 403;
        goto cleanup;
    }

    /* Only plain URLs are cached: a query string often carries a token or a per-user value. */
    char cache_key[CACHE_KEY_MAX];
    int cache_usable = 0;
    if (cache_is_enabled()) {
        if (strchr(parsed.path, '?') != NULL || cache_make_key(cache_key, sizeof(cache_key), parsed.host,
                                                               parsed.port, parsed.path) != 0) {
            cache_state = "cache=bypass";
        } else {
            cache_usable = 1;
            size_t hit_len = 0;
            unsigned char *hit = cache_lookup(cache_key, &hit_len);
            if (hit != NULL) {
                /* Served from memory: the destination was already validated when it was fetched. */
                send_all(client_fd, hit, hit_len);
                free(hit);
                log_decision = "allowed";
                log_status = 200;
                log_bytes = hit_len;
                cache_state = "cache=hit";
                goto cleanup;
            }
            cache_state = "cache=miss";
            stats.capture_limit = CACHE_DEFAULT_MAX_ENTRY_BYTES;
        }
    }

    FetchStatus fetch_status = fetch_and_relay(&parsed, client_fd, &stats);
    log_bytes = stats.bytes_relayed;

    if (cache_usable && fetch_status == FETCH_OK && stats.capture != NULL) {
        CacheVerdict verdict = cache_evaluate_response(stats.capture, stats.capture_len);
        if (verdict.cacheable &&
            cache_store(cache_key, stats.capture, stats.capture_len, verdict.ttl_seconds) == 0) {
            cache_state = "cache=stored";
        }
    }
    free(stats.capture); /* the single owner of the captured copy (cache_store made its own) */
    stats.capture = NULL;

    /* fetch_and_relay() only fails before any bytes are relayed for
     * FETCH_ERR_DNS and FETCH_ERR_CONNECT -- those are the only cases
     * where it's still safe to send our own response. FETCH_ERR_SEND and
     * FETCH_ERR_RECV mean the client may already have a partial raw
     * response on the wire; sending another response on top of that
     * would corrupt the stream, so we just stop. */
    if (fetch_status == FETCH_ERR_UNSAFE_ADDRESS) {
        /* Deliberately generic: the page names only a safe category, never the address. */
        sig.network_unsafe = 1;
        Decision net = decision_evaluate(&sig);
        send_block_page(client_fd, request_id, net.reason);
        log_decision = blocked_label(net.reason);
        log_status = 403;
    } else if (fetch_status == FETCH_ERR_DNS || fetch_status == FETCH_ERR_CONNECT) {
        char body[256];
        snprintf(body, sizeof(body), "502 Bad Gateway: %s\n", fetch_status_to_string(fetch_status));
        send_error_response(client_fd, 502, "Bad Gateway", body);
        log_decision = "bad_gateway";
        log_status = 502;
    } else if (fetch_status == FETCH_OK) {
        log_decision = "allowed";
        log_status = stats.origin_status;
    } else {
        log_decision = "relay_error";
        log_status = stats.origin_status;
    }

cleanup:;
    struct timespec end_ts;
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    long duration_ms = (long)(end_ts.tv_sec - start_ts.tv_sec) * 1000L +
                       (end_ts.tv_nsec - start_ts.tv_nsec) / 1000000L;
    /* Logged before drain_and_close() so the duration excludes the drain delay. */
    free(stats.capture); /* NULL on every path except an early exit after a capture started */
    if (cache_state != NULL) {
        extras_add(&extras, cache_state);
    }
    if (risk_known) {
        char risk_token[24];
        snprintf(risk_token, sizeof(risk_token), "risk=%d", decision_evaluate(&sig).risk_score);
        extras_add(&extras, risk_token);
    }
    log_request_ex(request_id, log_host, log_decision, log_status, log_bytes, duration_ms, extras.text);

    drain_and_close(client_fd);

    pthread_mutex_lock(&g_active_clients_mutex);
    g_active_clients--;
    pthread_mutex_unlock(&g_active_clients_mutex);

    return NULL;
}

int main(void) {
    /* A client closing its side of the connection must not kill the
     * process with SIGPIPE; failed writes are handled via send()'s
     * return value instead. */
    signal(SIGPIPE, SIG_IGN);

    /* A log file that can't be opened must never stop the proxy from serving. */
    const char *log_path = getenv("PROXY_LOG_FILE");
    if (log_path == NULL || log_path[0] == '\0') {
        log_path = DEFAULT_LOG_PATH;
    }
    if (logger_init(log_path) != 0) {
        fprintf(stderr, "proxy: warning: cannot open log file '%s'; request logging disabled\n",
                log_path);
    }

    /* Policy files: an explicitly configured file that cannot be read is a hard error
     * (fail closed -- never run with fewer rules than the operator asked for). A missing
     * DEFAULT file only produces a warning so a fresh checkout still starts. */
    const char *allow_env = getenv("PROXY_ALLOWLIST");
    const char *block_env = getenv("PROXY_BLOCKLIST");
    const char *allow_path = (allow_env && allow_env[0]) ? allow_env : DEFAULT_ALLOWLIST_PATH;
    const char *block_path = (block_env && block_env[0]) ? block_env : DEFAULT_BLOCKLIST_PATH;
    PolicyLoadReport report;
    if (policy_load(&g_policy, allow_path, block_path, &report) != 0) {
        fprintf(stderr, "proxy: out of memory loading policy files\n");
        return EXIT_FAILURE;
    }
    if ((report.block_file_missing && block_env && block_env[0]) ||
        (report.allow_file_missing && allow_env && allow_env[0])) {
        fprintf(stderr, "proxy: error: a policy file given via PROXY_ALLOWLIST/PROXY_BLOCKLIST "
                        "cannot be read; refusing to start with fewer rules than requested\n");
        policy_free(&g_policy);
        return EXIT_FAILURE;
    }
    if (report.block_file_missing) {
        fprintf(stderr, "proxy: warning: blocklist '%s' not found; no hosts are blocked\n", block_path);
    }
    if (report.block_malformed + report.allow_malformed > 0) {
        fprintf(stderr, "proxy: warning: ignored %zu malformed policy rule(s)\n",
                report.block_malformed + report.allow_malformed);
    }
    printf("proxy: policy loaded: %zu block rule(s), %zu allow rule(s), allowlist mode %s\n",
           g_policy.block_count, g_policy.allow_count, g_policy.allowlist_active ? "ON" : "off");

    /* TESTING ONLY: lets the automated tests use a loopback origin server. Off by default;
     * when on, every request to loopback/private networks is allowed, so say so loudly. */
    const char *allow_private = getenv("PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS");
    if (allow_private != NULL && strcmp(allow_private, "1") == 0) {
        origin_client_set_allow_private(1);
        fprintf(stderr, "proxy: WARNING: PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS=1 -- SSRF protection is "
                        "DISABLED. Use only for local testing.\n");
    }

    const char *cp = getenv("PROXY_CONNECT_PORT");
    if (cp != NULL && cp[0] != '\0') {
        char *endp = NULL;
        long v = strtol(cp, &endp, 10);
        if (*endp != '\0' || v < 1 || v > 65535) {
            fprintf(stderr, "proxy: error: PROXY_CONNECT_PORT must be a port number (1-65535)\n");
            return EXIT_FAILURE;
        }
        g_connect_port = (unsigned)v;
    }
    const char *ti = getenv("PROXY_TUNNEL_IDLE_SECONDS");
    if (ti != NULL && ti[0] != '\0') {
        char *endp = NULL;
        long v = strtol(ti, &endp, 10);
        if (*endp != '\0' || v < 1 || v > 3600) {
            fprintf(stderr, "proxy: error: PROXY_TUNNEL_IDLE_SECONDS must be 1-3600\n");
            return EXIT_FAILURE;
        }
        g_tunnel_idle_seconds = (int)v;
    }
    printf("proxy: CONNECT tunnelling allowed to port %u only\n", g_connect_port);

    /* Reputation: OFF unless an offline fixture file is configured (the default test mode).
     * A configured but unreadable file is a hard error, like the policy files. */
    static ReputationProvider rep_provider;
    const char *rep_fixture = getenv("PROXY_REPUTATION_FIXTURE");
    if (rep_fixture != NULL && rep_fixture[0] != '\0') {
        unsigned rep_timeout = 1500, rep_ttl = 300;
        const char *e = getenv("PROXY_REPUTATION_TIMEOUT_MS");
        if (e != NULL && e[0] != '\0') {
            char *endp = NULL;
            long v = strtol(e, &endp, 10);
            if (*endp != '\0' || v < 50 || v > 30000) {
                fprintf(stderr, "proxy: error: PROXY_REPUTATION_TIMEOUT_MS must be 50-30000\n");
                return EXIT_FAILURE;
            }
            rep_timeout = (unsigned)v;
        }
        e = getenv("PROXY_REPUTATION_TTL_SECONDS");
        if (e != NULL && e[0] != '\0') {
            char *endp = NULL;
            long v = strtol(e, &endp, 10);
            if (*endp != '\0' || v < 1 || v > 86400) {
                fprintf(stderr, "proxy: error: PROXY_REPUTATION_TTL_SECONDS must be 1-86400\n");
                return EXIT_FAILURE;
            }
            rep_ttl = (unsigned)v;
        }
        size_t rep_bad = 0;
        if (reputation_fixture_load(rep_fixture, getenv("PROXY_REPUTATION_QUERY_LOG"), &rep_provider, &rep_bad) != 0 ||
            reputation_init(&rep_provider, rep_timeout, rep_ttl) != 0) {
            fprintf(stderr, "proxy: error: cannot load the reputation fixture file; refusing to start\n");
            return EXIT_FAILURE;
        }
        printf("proxy: reputation checks ON (offline fixture provider, timeout %u ms, %zu malformed line(s) ignored)\n",
               rep_timeout, rep_bad);
    }

    const char *cache_env = getenv("PROXY_CACHE");
    if (cache_env != NULL && strcmp(cache_env, "0") == 0) {
        printf("proxy: response cache disabled (PROXY_CACHE=0)\n");
    } else if (cache_init(CACHE_DEFAULT_MAX_ENTRIES, CACHE_DEFAULT_MAX_TOTAL_BYTES,
                          CACHE_DEFAULT_MAX_ENTRY_BYTES) != 0) {
        fprintf(stderr, "proxy: warning: could not allocate the response cache; caching disabled\n");
    }

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

        /* Check bounded concurrency limit */
        pthread_mutex_lock(&g_active_clients_mutex);
        if (g_active_clients >= MAX_CONCURRENT_CLIENTS) {
            pthread_mutex_unlock(&g_active_clients_mutex);
            send_error_response(client_fd, 503, "Service Unavailable",
                                "503 Service Unavailable: Maximum concurrent connections reached.\n");
            log_request(logger_next_request_id(), "-", "overloaded", 503, 0, 0);
            close(client_fd);
            continue;
        }
        g_active_clients++;
        pthread_mutex_unlock(&g_active_clients_mutex);

        /* Allocate heap-owned ClientArgs to avoid loop-variable races */
        ClientArgs *args = (ClientArgs *)malloc(sizeof(ClientArgs));
        if (args == NULL) {
            perror("malloc");
            log_request(logger_next_request_id(), "-", "internal_error", 0, 0, 0);
            close(client_fd);
            pthread_mutex_lock(&g_active_clients_mutex);
            g_active_clients--;
            pthread_mutex_unlock(&g_active_clients_mutex);
            continue;
        }
        args->client_fd = client_fd;

        pthread_t tid;
        int err = pthread_create(&tid, NULL, handle_client, args);
        if (err != 0) {
            fprintf(stderr, "pthread_create failed: %s\n", strerror(err));
            log_request(logger_next_request_id(), "-", "internal_error", 0, 0, 0);
            /* On thread creation failure: close socket, free args, decrement count */
            close(client_fd);
            free(args);
            pthread_mutex_lock(&g_active_clients_mutex);
            g_active_clients--;
            pthread_mutex_unlock(&g_active_clients_mutex);
            continue;
        }
    }

    close(listen_fd);
    reputation_shutdown();
    cache_destroy();
    policy_free(&g_policy);
    return 0;
}