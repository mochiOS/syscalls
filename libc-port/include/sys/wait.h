#ifndef MOCHIOS_SYS_WAIT_H
#define MOCHIOS_SYS_WAIT_H
#include <signal.h>

#if __POSIX_VISIBLE >= 200809 || __XSI_VISIBLE >= 500
#include_next <sys/wait.h>

typedef enum { P_ALL = 0, P_PID = 1, P_PGID = 2 } idtype_t;
#define WEXITED 4
#define WSTOPPED WUNTRACED
#define WNOWAIT 16

#ifdef __cplusplus
extern "C" {
#endif
int waitid(idtype_t, id_t, siginfo_t *, int);
#ifdef __cplusplus
}
#endif
#endif /* POSIX.1-2008 / XSI waitid declarations */
#endif
