#ifndef _MOCHI_HANDLE_H
#define _MOCHI_HANDLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Borrow a live, caller-owned file Handle and install a duplicate as a POSIX
 * FD. The source must remain live throughout this call and is never closed.
 * It must refer to a regular file or directory and permit DUPLICATE, TRANSFER,
 * and READ and/or WRITE. Metadata is checked
 * through the inherited POSIX endpoint; no path is resolved or authorized.
 * flags accepts only zero or O_CLOEXEC (from <fcntl.h>). Access mode follows
 * the actual Handle rights; shared offset and mutable status flags are kept.
 * Returns an FD, or -1 with errno set. Failure closes only temporary ownership.
 */
int mochi_fd_from_file_handle(uint32_t handle, int flags);

#ifdef __cplusplus
}
#endif

#endif
