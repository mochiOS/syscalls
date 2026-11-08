#ifndef _MOCHIOS_SYS_FILE_H
#define _MOCHIOS_SYS_FILE_H
#include <fcntl.h>
#include <unistd.h>
#define L_SET SEEK_SET
#define L_INCR SEEK_CUR
#define L_XTND SEEK_END
#ifndef LOCK_SH
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Advisory locks are shared by aliases of one open file description. */
int flock(int, int);
#ifdef __cplusplus
}
#endif
#endif
