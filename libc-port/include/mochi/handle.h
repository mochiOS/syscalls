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

struct mochi_fd_handle {
    uint32_t handle;
    uint32_t reserved;
    uint64_t rights;
    uint64_t metadata;
};

/* Export a caller-owned FD as one independently owned native Handle. No path
 * is resolved and the FD remains open. requested_rights must be a subset of
 * the FD's rights and include READ and/or WRITE permitted by its access mode.
 * The source must permit DUPLICATE; IPC use additionally needs TRANSFER in
 * requested_rights. Metadata uses the shared POSIX inherited-FD encoding,
 * preserving descriptor flags and narrowing access to the requested rights.
 * On success, the caller must close result->handle with HandleClose. Do not
 * use close(), which accepts an FD. Non-native legacy stdio is unsupported.
 * Returns 0, or -1 with errno set. Failure reclaims any new native reference;
 * the result structure is unspecified on failure.
 */
int mochi_fd_export(int fd, uint64_t requested_rights,
                    struct mochi_fd_handle *result);

#ifdef __cplusplus
}
#endif

#endif
