#ifndef _SYS_POLL_H_
#define _SYS_POLL_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#ifndef _NFDS_T_DECLARED
typedef unsigned int nfds_t;
#define _NFDS_T_DECLARED
#endif

struct pollfd {
    int fd;
    short events;
    short revents;
};

#define POLLIN      0x0001
#define POLLPRI     0x0002
#define POLLOUT     0x0004
#define POLLERR     0x0008
#define POLLHUP     0x0010
#define POLLNVAL    0x0020
#define POLLRDNORM  0x0040
#define POLLWRNORM  POLLOUT
#define POLLRDBAND  0x0080
#define POLLWRBAND  0x0100
#define INFTIM      (-1)

__BEGIN_DECLS
int poll(struct pollfd[], nfds_t, int);
__END_DECLS

#endif
