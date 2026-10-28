#ifndef _ARPA_INET_H_
#define _ARPA_INET_H_

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif
int inet_pton(int, const char *, void *);
const char *inet_ntop(int, const void *, char *, socklen_t);
#ifdef __cplusplus
}
#endif

#endif
