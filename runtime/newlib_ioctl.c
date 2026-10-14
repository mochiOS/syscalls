#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/ioctl.h>

extern int __mochios_fd_set_nonblocking(int fd, int enabled);

int ioctl(int fd, unsigned long request, ...) {
    /* Descriptor-local validation: no provider request and no extra argument
     * access are needed to reject a bad FD or unsupported request. */
    if (fcntl(fd, F_GETFD, 0) == -1)
        return -1;
    switch (request) {
    case TCGETS:
    case TCSETS:
    case TCSETSW:
    case TCSETSF:
    case TIOCGPGRP:
    case TIOCSPGRP:
    case TIOCGWINSZ:
    case TIOCSWINSZ:
    case FIONBIO:
        break;
    default:
        errno = ENOTTY;
        return -1;
    }

    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    if (argument == NULL) {
        errno = EFAULT;
        return -1;
    }

    switch (request) {
    case FIONBIO:
        return __mochios_fd_set_nonblocking(fd, *(const int *)argument != 0);
    case TCGETS:
        return tcgetattr(fd, argument);
    case TCSETS:
        return tcsetattr(fd, TCSANOW, argument);
    case TCSETSW:
        return tcsetattr(fd, TCSADRAIN, argument);
    case TCSETSF:
        return tcsetattr(fd, TCSAFLUSH, argument);
    case TIOCGWINSZ:
        return tcgetwinsize(fd, argument);
    case TIOCSWINSZ:
        return tcsetwinsize(fd, argument);
    case TIOCGPGRP: {
        pid_t group = tcgetpgrp(fd);
        if (group == (pid_t)-1)
            return -1;
        *(pid_t *)argument = group;
        return 0;
    }
    case TIOCSPGRP:
        return tcsetpgrp(fd, *(const pid_t *)argument);
    default:
        /* Every request reaching this point was classified above. */
        errno = ENOTTY;
        return -1;
    }
}
