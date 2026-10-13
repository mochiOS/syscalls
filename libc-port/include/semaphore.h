#ifndef _MOCHIOS_SEMAPHORE_H_
#define _MOCHIOS_SEMAPHORE_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <time.h>

/* In-place state: shared mappings provide identity, not a process-local ID. */
typedef struct {
    uint64_t __count;
    uint32_t __initialized;
    uint32_t __reserved;
} sem_t;

#define SEM_VALUE_MAX 2147483647
#define SEM_FAILED ((sem_t *)0)

__BEGIN_DECLS
int sem_init(sem_t *, int, unsigned int);
int sem_destroy(sem_t *);
int sem_post(sem_t *);
int sem_getvalue(sem_t *, int *);
int sem_trywait(sem_t *);
int sem_wait(sem_t *);
int sem_timedwait(sem_t *, const struct timespec *);
sem_t *sem_open(const char *, int, ...);
int sem_close(sem_t *);
int sem_unlink(const char *);
#if __GNU_VISIBLE
int sem_clockwait(sem_t *, clockid_t, const struct timespec *);
#endif
__END_DECLS

#endif
