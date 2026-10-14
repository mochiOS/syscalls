#ifndef _SETJMP_H_
#define _SETJMP_H_

#include <_ansi.h>
#include <sys/cdefs.h>
#include <machine/setjmp.h>

_BEGIN_STD_C
void longjmp(jmp_buf, int) __dead2;
int setjmp(jmp_buf) __returns_twice;

#if __POSIX_VISIBLE
/* Both environments retain handler ancestry. Plain setjmp/_setjmp use
   System V semantics: they do not save or restore the signal mask. */
typedef jmp_buf sigjmp_buf;
int sigsetjmp(sigjmp_buf, int) __returns_twice;
void siglongjmp(sigjmp_buf, int) __dead2;
int _setjmp(jmp_buf) __returns_twice;
void _longjmp(jmp_buf, int) __dead2;
#endif
_END_STD_C

#endif
