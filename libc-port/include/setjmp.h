#ifndef _SETJMP_H_
#define _SETJMP_H_

#include <_ansi.h>
#include <sys/cdefs.h>
#include <machine/setjmp.h>
#include <stdint.h>

_BEGIN_STD_C
void longjmp(jmp_buf, int) __dead2;
int setjmp(jmp_buf) __returns_twice;

#if __POSIX_VISIBLE
/* x86-64 registers plus thread-local continuation/mask metadata. Opaque to
   applications; unlike jmp_buf this also records live handler ancestry. */
typedef uint64_t sigjmp_buf[15];
int sigsetjmp(sigjmp_buf, int) __returns_twice;
void siglongjmp(sigjmp_buf, int) __dead2;
#endif
_END_STD_C

#endif
