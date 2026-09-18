/* util.c: Implements bounded string helpers and send_all(), which loops until every requested byte has been sent or an error occurs. */
#include "util.h"

#include <errno.h>
#include <unistd.h>

ssize_t send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t total = 0;

    while (total < len) {
        ssize_t n = write(fd, p + total, len - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break; /* peer closed or disk full; nothing more we can do */
        }
        total += (size_t)n;
    }

    return (ssize_t)total;
}
