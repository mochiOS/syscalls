/* Included by the mochiOS-specific branch of newlib's sys/signal.h. */
#ifndef _MOCHIOS_SIGINFO_H
#define _MOCHIOS_SIGINFO_H

typedef struct {
    int si_signo;
    int si_code;
    union sigval si_value;
    int si_errno;
    pid_t si_pid;
    uid_t si_uid;
    unsigned short __reserved_uid;
    int si_status;
    void *si_addr;
} siginfo_t;

#define SI_KERNEL 128
/* Existing newlib SI_* source codes occupy 1..5. */
#define SEGV_MAPERR 0x100
#define SEGV_ACCERR 0x101
#define BUS_ADRALN 0x100
#define BUS_ADRERR 0x101
#define BUS_OBJERR 0x102

#endif
