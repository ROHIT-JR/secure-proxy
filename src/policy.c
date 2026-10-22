/* policy.c: Implements loading of config/allowlist.txt and config/blocklist.txt and the SSRF-safe address checks used to accept or reject a destination. */

#define _POSIX_C_SOURCE 200809L

#include "policy.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POLICY_LINE_MAX 1024
#define POLICY_HOST_MAX 253 /* longest valid DNS name */

/* Lowercases `in` into `out` and strips a port and trailing dots, so
 * "Example.COM.", "example.com:8080" and "example.com" all compare equal. */
static void normalize_host(const char *in, char *out, size_t out_len) {
    size_t o = 0;
    for (size_t i = 0; in != NULL && in[i] != '\0' && o + 1 < out_len; i++) {
        if (in[i] == ':') {
            break;
        }
        out[o++] = (char)tolower((unsigned char)in[i]);
    }
    while (o > 0 && out[o - 1] == '.') {
        o--;
    }
    out[o] = '\0';
}

/* Parses one rule line. Returns 1 = valid rule stored in *rule, 0 = blank/comment, -1 = malformed. */
static int parse_rule_line(const char *line, PolicyRule *rule) {
    char buf[POLICY_LINE_MAX];
    size_t n = strcspn(line, "#\r\n"); /* cut an inline or whole-line comment */
    if (n >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';

    char *start = buf;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }
    size_t len = strlen(start);
    while (len > 0 && isspace((unsigned char)start[len - 1])) {
        start[--len] = '\0';
    }
    if (len == 0) {
        return 0;
    }

    int subdomains = 0;
    if (start[0] == '.') {
        subdomains = 1;
        start++;
        len--;
    }
    while (len > 0 && start[len - 1] == '.') { /* tolerate "example.com." */
        start[--len] = '\0';
    }
    if (len == 0 || len > POLICY_HOST_MAX) {
        return -1;
    }

    /* Only plain hostname characters; no '*', '/', ':', spaces, or empty labels. */
    char prev = '.';
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)start[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.')) {
            return -1;
        }
        if (c == '.' && prev == '.') {
            return -1;
        }
        prev = (char)c;
    }

    for (size_t i = 0; i < len; i++) {
        rule->host[i] = (char)tolower((unsigned char)start[i]);
    }
    rule->host[len] = '\0';
    rule->include_subdomains = subdomains;
    return 1;
}

static int append_rule(PolicyRule **rules, size_t *count, const PolicyRule *rule) {
    PolicyRule *grown = realloc(*rules, (*count + 1) * sizeof(PolicyRule));
    if (grown == NULL) {
        return -1;
    }
    grown[*count] = *rule;
    *rules = grown;
    (*count)++;
    return 0;
}

/* Loads one file. *missing is set if it cannot be opened. *saw_text is set if
 * the file had any non-blank, non-comment line (used for fail-closed allowlists). */
static int load_file(const char *path, PolicyRule **rules, size_t *count, size_t *loaded,
                     size_t *malformed, int *missing, int *saw_text) {
    *missing = 0;
    *saw_text = 0;
    if (path == NULL) {
        *missing = 1;
        return 0;
    }
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        *missing = 1;
        return 0;
    }

    char line[POLICY_LINE_MAX];
    while (fgets(line, sizeof(line), f) != NULL) {
        /* A line longer than the buffer is malformed; discard the rest of it. */
        size_t got = strlen(line);
        int too_long = (got == sizeof(line) - 1 && line[got - 1] != '\n');
        if (too_long) {
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') {
            }
            (*malformed)++;
            *saw_text = 1;
            continue;
        }

        PolicyRule rule;
        int r = parse_rule_line(line, &rule);
        if (r == 0) {
            continue;
        }
        *saw_text = 1;
        if (r < 0) {
            (*malformed)++;
            continue;
        }
        if (append_rule(rules, count, &rule) != 0) {
            fclose(f);
            return -1;
        }
        (*loaded)++;
    }
    fclose(f);
    return 0;
}

int policy_load(Policy *p, const char *allowlist_path, const char *blocklist_path,
                PolicyLoadReport *report) {
    PolicyLoadReport local;
    if (report == NULL) {
        report = &local;
    }
    memset(report, 0, sizeof(*report));
    memset(p, 0, sizeof(*p));

    int saw_block_text = 0, saw_allow_text = 0;
    if (load_file(blocklist_path, &p->block_rules, &p->block_count, &report->block_loaded,
                  &report->block_malformed, &report->block_file_missing, &saw_block_text) != 0 ||
        load_file(allowlist_path, &p->allow_rules, &p->allow_count, &report->allow_loaded,
                  &report->allow_malformed, &report->allow_file_missing, &saw_allow_text) != 0) {
        policy_free(p);
        return -1;
    }
    p->allowlist_active = saw_allow_text; /* fail closed: any rule text turns the mode on */
    return 0;
}

static int rule_matches(const PolicyRule *rule, const char *host) {
    if (strcmp(host, rule->host) == 0) {
        return 1;
    }
    if (rule->include_subdomains) {
        size_t hl = strlen(host), rl = strlen(rule->host);
        /* Require the dot boundary so ".example.com" never matches "notexample.com". */
        if (hl > rl + 1 && host[hl - rl - 1] == '.' && strcmp(host + (hl - rl), rule->host) == 0) {
            return 1;
        }
    }
    return 0;
}

PolicyDecision policy_check_host(const Policy *p, const char *host) {
    char norm[POLICY_HOST_MAX + 2];
    normalize_host(host, norm, sizeof(norm));

    for (size_t i = 0; i < p->block_count; i++) {
        if (rule_matches(&p->block_rules[i], norm)) {
            return POLICY_DENY_BLOCKLIST;
        }
    }
    if (p->allowlist_active) {
        for (size_t i = 0; i < p->allow_count; i++) {
            if (rule_matches(&p->allow_rules[i], norm)) {
                return POLICY_ALLOW;
            }
        }
        return POLICY_DENY_NOT_ALLOWLISTED;
    }
    return POLICY_ALLOW;
}

void policy_free(Policy *p) {
    free(p->block_rules);
    free(p->allow_rules);
    memset(p, 0, sizeof(*p));
}
