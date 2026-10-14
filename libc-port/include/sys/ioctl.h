#ifndef _MOCHIOS_SYS_IOCTL_H_
#define _MOCHIOS_SYS_IOCTL_H_

#include <sys/cdefs.h>
#include <sys/termios.h>

/* Compatibility request numbers belong to libc, never the native mnu ABI. */
#define TCGETS      0x5401UL
#define TCSETS      0x5402UL
#define TCSETSW     0x5403UL
#define TCSETSF     0x5404UL
#define TIOCGPGRP   0x540FUL
#define TIOCSPGRP   0x5410UL
#define TIOCGWINSZ  0x5413UL
#define TIOCSWINSZ  0x5414UL
#define FIONBIO     0x5421UL

__BEGIN_DECLS
int ioctl(int, unsigned long, ...);
__END_DECLS

#endif /* _MOCHIOS_SYS_IOCTL_H_ */
