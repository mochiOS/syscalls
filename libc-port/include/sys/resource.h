#ifndef _SYS_RESOURCE_H_
#define _SYS_RESOURCE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>

#ifndef _RLIM_T_DECLARED
typedef uint64_t rlim_t;
#define _RLIM_T_DECLARED
#endif

#define RLIM_INFINITY UINT64_MAX

#define RLIMIT_CPU 0
#define RLIMIT_FSIZE 1
#define RLIMIT_DATA 2
#define RLIMIT_STACK 3
#define RLIMIT_CORE 4
#define RLIMIT_RSS 5
#define RLIMIT_NPROC 6
#define RLIMIT_NOFILE 7
#define RLIMIT_MEMLOCK 8
#define RLIMIT_AS 9

struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

#define	RUSAGE_SELF	0		/* calling process */
#define	RUSAGE_CHILDREN	-1		/* terminated child processes */
#if __GNU_VISIBLE
#define	RUSAGE_THREAD	1
#endif

struct rusage {
  	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
	long ru_maxrss;		/* peak resident RAM, in KiB */
};

int	getrusage (int, struct rusage*);
int	getrlimit (int, struct rlimit *);
int	setrlimit (int, const struct rlimit *);
#if __GNU_VISIBLE
int	prlimit (pid_t, int, const struct rlimit *, struct rlimit *);
#endif

#ifdef __cplusplus
}
#endif
#endif /* !_SYS_RESOURCE_H_ */
