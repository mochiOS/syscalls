#ifndef _PTY_H_
#define _PTY_H_

#include <sys/cdefs.h>

struct termios;
struct winsize;

__BEGIN_DECLS

int openpty(int *, int *, char *, const struct termios *, const struct winsize *);
int login_tty(int);

__END_DECLS

#endif /* _PTY_H_ */
