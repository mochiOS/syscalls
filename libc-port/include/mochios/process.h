#ifndef MOCHIOS_PROCESS_H
#define MOCHIOS_PROCESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** A single kernel snapshot of this process's resident user RAM, in bytes.
 * Shared frames count once per mapped leaf in this address space. Inaccessible
 * retained RAM counts; virtual reservations and device mappings do not.
 * peak_bytes is the independent high-water mark over the process lifetime.
 */
struct mochios_process_memory_usage {
    uint64_t current_bytes;
    uint64_t peak_bytes;
};

/** Query only the calling process; this grants no rights over other processes.
 * Pass sizeof(*usage) as size. Returns 0 on success, or -1 and sets errno on
 * failure. An incorrect size is EINVAL and an inaccessible output is EFAULT.
 * No snapshot is published when the query fails. This function is thread-safe;
 * the snapshot is observational and does not reserve or pin memory.
 */
int mochios_process_memory_read(struct mochios_process_memory_usage *usage,
                               size_t size);

#ifdef __cplusplus
}
#endif
#endif
