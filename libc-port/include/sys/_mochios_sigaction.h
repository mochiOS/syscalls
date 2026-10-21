#ifndef _MOCHIOS_SIGACTION_H
#define _MOCHIOS_SIGACTION_H

#define SA_SIGINFO 0x4
#define SA_ONSTACK 0x8
#define SA_NODEFER 0x40000000
#define SA_RESETHAND ((int)0x80000000U)
/* Keep the non-RTEMS newlib layout: handler union, mask, flags. */
struct sigaction {
    union {
        _sig_func_ptr sa_handler;
#if defined(_POSIX_REALTIME_SIGNALS) || __POSIX_VISIBLE >= 199309
        void (*sa_sigaction)(int, siginfo_t *, void *);
#endif
    };
    sigset_t sa_mask;
    int sa_flags;
};

#endif
