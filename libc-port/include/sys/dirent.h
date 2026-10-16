#ifndef _SYS_DIRENT_H_
#define _SYS_DIRENT_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <stdint.h>

/* Matches the process-local newlib runtime, not a kernel directory ABI. */
struct dirent {
    uint64_t d_ino;
    uint8_t d_type;
    char d_name[256];
};

typedef struct __mochios_dir_stream DIR;

#if __BSD_VISIBLE
#define MAXNAMLEN 255
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14
#endif

#endif /* _SYS_DIRENT_H_ */
