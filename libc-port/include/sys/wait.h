#ifndef MOCHIOS_SYS_WAIT_H
#define MOCHIOS_SYS_WAIT_H
#include <sys/types.h>
#include <signal.h>

#define WNOHANG 1
#define WUNTRACED 2
#define WCONTINUED 8

#define WIFEXITED(w) (((w) & 0xff) == 0)
#define WIFSIGNALED(w) (((w) & 0x7f) > 0 && ((w) & 0x7f) < 0x7f)
#define WIFSTOPPED(w) (((w) & 0xff) == 0x7f)
#define WIFCONTINUED(w) ((w) == 0xffff)
#define WEXITSTATUS(w) (((w) >> 8) & 0xff)
#define WTERMSIG(w) ((w) & 0x7f)
#define WSTOPSIG(w) WEXITSTATUS(w)

#if __POSIX_VISIBLE >= 200809 || __XSI_VISIBLE >= 500
typedef enum { P_ALL = 0, P_PID = 1, P_PGID = 2 } idtype_t;
#define WEXITED 4
#define WSTOPPED WUNTRACED
#define WNOWAIT 16
#endif

#ifdef __cplusplus
extern "C" {
#endif
pid_t wait(int *);
pid_t waitpid(pid_t, int *, int);
pid_t _wait(int *);
#if __POSIX_VISIBLE >= 200809 || __XSI_VISIBLE >= 500
int waitid(idtype_t, id_t, siginfo_t *, int);
#endif
#ifdef __cplusplus
}
#endif
#endif
