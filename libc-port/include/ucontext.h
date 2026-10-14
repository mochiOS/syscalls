#ifndef _MOCHIOS_UCONTEXT_H
#define _MOCHIOS_UCONTEXT_H

#include <stdint.h>
#include <signal.h>

/* mochiOS x86-64 POSIX ABI. This is not the Linux ucontext binary ABI. */
typedef uint64_t greg_t;
enum {
    REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
    REG_RDI, REG_RSI, REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX,
    REG_RSP, REG_RIP, REG_EFL, NGREG
};
typedef greg_t gregset_t[NGREG];
typedef struct {
    gregset_t gregs;
    unsigned char fpregs[512] __attribute__((aligned(16)));
} mcontext_t;

typedef struct ucontext {
    uint64_t uc_flags;
    struct ucontext *uc_link;
    sigset_t uc_sigmask;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
} ucontext_t;

#endif
