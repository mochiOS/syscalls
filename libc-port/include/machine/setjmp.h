#ifndef _MOCHIOS_MACHINE_SETJMP_H
#define _MOCHIOS_MACHINE_SETJMP_H

#include <_ansi.h>

/* Registers plus thread-local handler ancestry; shared with sigjmp_buf.
   C code using the previous eight-word ABI must be rebuilt. */
#if defined(__x86_64__)
#define _JBLEN 15
#elif defined(__aarch64__)
/* X19..X30, SP, preserved D8..D15 halves, then handler ancestry. */
#define _JBLEN 28
#else
#error "mochiOS jump context has no layout for this architecture"
#endif
#define _JBTYPE long long
_BEGIN_STD_C
typedef _JBTYPE jmp_buf[_JBLEN];
_END_STD_C

#endif
