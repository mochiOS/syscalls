#include <reent.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stdio.h>

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

/* Share the actual FILE lock with newlib's internal stdio operations. These
 * ownership operations are not cancellation points. String-only pseudo-FILEs
 * have no initialized lock, just as in newlib's internal locking macros. */
void flockfile(FILE *stream) {
    _flockfile(stream);
}

int ftrylockfile(FILE *stream) {
    if (stream->_flags & __SSTR) {
        return 0;
    }
    /* The retargetable lock reports one on acquisition; POSIX reports zero. */
    return __lock_try_acquire_recursive(stream->_lock) ? 0 : 1;
}

void funlockfile(FILE *stream) {
    _funlockfile(stream);
}

/* Use the same allocation, stream locking and cancellation scopes as newlib.
 * The buffer is caller-owned and remains freeable after errors/cancellation. */
ssize_t getdelim(char **lineptr, size_t *capacity, int delimiter, FILE *stream) {
    return __getdelim(lineptr, capacity, delimiter, stream);
}

ssize_t getline(char **lineptr, size_t *capacity, FILE *stream) {
    return __getdelim(lineptr, capacity, '\n', stream);
}
