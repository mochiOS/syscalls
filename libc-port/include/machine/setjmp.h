#ifndef _MOCHIOS_MACHINE_SETJMP_H
#define _MOCHIOS_MACHINE_SETJMP_H

#include <_ansi.h>
#if !defined(__x86_64__)
#error "mochiOS jump context is currently implemented for x86-64 only"
#endif

/* Registers plus thread-local handler ancestry; shared with sigjmp_buf.
   C code using the previous eight-word ABI must be rebuilt. */
#define _JBLEN 15
#define _JBTYPE long long
_BEGIN_STD_C
typedef _JBTYPE jmp_buf[_JBLEN];
_END_STD_C

#endif
