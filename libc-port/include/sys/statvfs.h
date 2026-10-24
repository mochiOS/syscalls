#ifndef MOCHIOS_SYS_STATVFS_H
#define MOCHIOS_SYS_STATVFS_H
#include <sys/types.h>

/* Process-local C ABI. No kernel or IPC structure uses this layout. */
struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    fsblkcnt_t f_blocks;
    fsblkcnt_t f_bfree;
    fsblkcnt_t f_bavail;
    fsfilcnt_t f_files;
    fsfilcnt_t f_ffree;
    fsfilcnt_t f_favail;
    unsigned long f_fsid;
    unsigned long f_flag;
    unsigned long f_namemax;
};
#define ST_RDONLY 1
#define ST_NOSUID 2
#ifdef __cplusplus
extern "C" {
#endif
int statvfs(const char *, struct statvfs *);
int fstatvfs(int, struct statvfs *);
#ifdef __cplusplus
}
#endif
#endif
