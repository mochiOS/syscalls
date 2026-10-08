#ifndef _SYS_TERMIOS_H_
#define _SYS_TERMIOS_H_

#include <sys/cdefs.h>
#include <sys/types.h>

typedef unsigned char cc_t;
typedef unsigned int speed_t;
typedef unsigned int tcflag_t;

#define NCCS 32

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_cc[NCCS];
    speed_t c_ispeed;
    speed_t c_ospeed;
};

#define IGNBRK  (1U << 0)
#define BRKINT  (1U << 1)
#define IGNPAR  (1U << 2)
#define PARMRK  (1U << 3)
#define INPCK   (1U << 4)
#define ISTRIP  (1U << 5)
#define INLCR   (1U << 6)
#define IGNCR   (1U << 7)
#define ICRNL   (1U << 8)
#define IXON    (1U << 10)
#define IXOFF   (1U << 12)
#define IUTF8   (1U << 14)

#define OPOST   (1U << 0)
#define ONLCR   (1U << 2)

#define CSIZE   (3U << 4)
#define CS8     (3U << 4)
#define CREAD   (1U << 7)
#define PARENB  (1U << 8)
#define HUPCL   (1U << 10)
#define CLOCAL  (1U << 11)

#define ISIG    (1U << 0)
#define ICANON  (1U << 1)
#define ECHO    (1U << 3)
#define ECHOE   (1U << 4)
#define ECHOK   (1U << 5)
#define ECHONL  (1U << 6)
#define NOFLSH  (1U << 7)
#define TOSTOP  (1U << 8)
#define IEXTEN  (1U << 15)

#define VINTR     0
#define VQUIT     1
#define VERASE    2
#define VKILL     3
#define VEOF      4
#define VTIME     5
#define VMIN      6
#define VSTART    8
#define VSTOP     9
#define VSUSP    10
#define VEOL     11
#define VREPRINT 12
#define VDISCARD 13
#define VWERASE  14
#define VLNEXT   15
#define VEOL2    16

#define _POSIX_VDISABLE 0

#define TCSANOW   0
#define TCSADRAIN 1
#define TCSAFLUSH 2

#define TCIFLUSH  0
#define TCOFLUSH  1
#define TCIOFLUSH 2

#define B0       0U
#define B50      50U
#define B75      75U
#define B110     110U
#define B134     134U
#define B150     150U
#define B200     200U
#define B300     300U
#define B600     600U
#define B1200    1200U
#define B1800    1800U
#define B2400    2400U
#define B4800    4800U
#define B9600    9600U
#define B19200   19200U
#define B38400   38400U
#define B57600   57600U
#define B115200  115200U

__BEGIN_DECLS

int tcgetattr(int, struct termios *);
int tcsetattr(int, int, const struct termios *);
int tcdrain(int);
int tcflush(int, int);
pid_t tcgetpgrp(int);
int tcsetpgrp(int, pid_t);
speed_t cfgetispeed(const struct termios *);
speed_t cfgetospeed(const struct termios *);
int cfsetispeed(struct termios *, speed_t);
int cfsetospeed(struct termios *, speed_t);
int cfsetspeed(struct termios *, speed_t);
void cfmakeraw(struct termios *);

__END_DECLS

#endif /* _SYS_TERMIOS_H_ */
