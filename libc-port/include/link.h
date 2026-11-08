#ifndef _MOCHIOS_LINK_H
#define _MOCHIOS_LINK_H
#include <stddef.h>
#include <elf.h>
#define ElfW(type) Elf64_##type
struct dl_phdr_info {
    uint64_t dlpi_addr;
    const char *dlpi_name;
    const Elf64_Phdr *dlpi_phdr;
    uint16_t dlpi_phnum;
};
/* Callback size advertises this common prefix only. GNU dynamic-TLS/counter
   suffixes are intentionally absent. Inspect type/flags using ELF constants. */
#ifdef __cplusplus
extern "C" {
#endif
/* Visit a snapshot without holding a loader mutex during callbacks. Return
   the first nonzero callback result, or zero after all objects. Snapshot
   pointers expire when this call returns. A missing initial graph or failed
   snapshot returns -1/errno; callbacks must respect the supplied byte size. */
int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);
#ifdef __cplusplus
}
#endif
#endif
