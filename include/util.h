#pragma once
/* util.h: Declares small shared helpers such as bounded string copies and the send_all() reliable-write wrapper. */

#include <stddef.h>
#include <sys/types.h>

/*
 * Writes exactly len bytes from buf to fd, looping over write() since a
 * single call is not guaranteed to write everything at once (true for
 * sockets, pipes, and regular files alike). Returns the number of bytes
 * written on success (== len unless the peer closed early), or -1 if
 * write() fails with a real error.
 */
ssize_t send_all(int fd, const void *buf, size_t len);
