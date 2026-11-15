#ifndef _MOCHIOS_UCONTEXT_H
#define _MOCHIOS_UCONTEXT_H

#include <stdint.h>
#include <signal.h>

/* mochiOS native POSIX continuation, selected for the compilation target. */
typedef uint64_t greg_t;
#if defined(__x86_64__)
enum {
    REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
    REG_RDI, REG_RSI, REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX,
    REG_RSP, REG_RIP, REG_EFL, NGREG
};
#elif defined(__aarch64__)
enum {
    REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7,
    REG_X8, REG_X9, REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
    REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
    REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30,
    REG_SP, REG_PC, REG_PSTATE, NGREG
};
#else
#error "mochiOS ucontext has no register layout for this architecture"
#endif
typedef greg_t gregset_t[NGREG];
typedef struct {
    gregset_t gregs;
    unsigned char fpregs[512] __attribute__((aligned(16)));
#if defined(__aarch64__)
    uint64_t fpcr;
    uint64_t fpsr;
#endif
} mcontext_t;

typedef struct ucontext {
    uint64_t uc_flags;
    struct ucontext *uc_link;
    sigset_t uc_sigmask;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
} ucontext_t;

#endif
