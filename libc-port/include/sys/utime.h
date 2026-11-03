#ifndef _SYS_UTIME_H
#define _SYS_UTIME_H
#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
struct utimbuf { time_t actime; time_t modtime; };
/* Uses the caller's filesystem authority; NULL uses current server time. */
int utime(const char *, const struct utimbuf *);
#ifdef __cplusplus
}
#endif
#endif
