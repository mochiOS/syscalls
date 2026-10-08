#include <reent.h>
#include <stddef.h>
#include <string.h>

extern void __sinit(struct _reent *);

size_t __mochios_reent_size(void) {
    return sizeof(struct _reent);
}

void __mochios_reent_initialize(void *storage) {
    struct _reent *reent = storage;

    memset(reent, 0, sizeof(*reent));
    _REENT_INIT_PTR(reent);
    __sinit(reent);
}

void __mochios_reent_destroy(void *storage) {
    _reclaim_reent(storage);
}
