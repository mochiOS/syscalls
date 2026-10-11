#include <reent.h>
#include <errno.h>
#include <signal.h>
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

/* Newlib's default raise uses process-wide kill(getpid(), sig). Retarget it
 * to the authenticated calling-thread path, including reentrant callers. */
int _raise_r(struct _reent *reent, int signal) {
    int result = raise(signal);
    if (result != 0) {
        _REENT_ERRNO(reent) = errno;
    }
    return result;
}
