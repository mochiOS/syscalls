#ifndef _ARPA_INET_H_
#define _ARPA_INET_H_

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Legacy conversion; strict applications should use inet_pton instead. */
int inet_aton(const char *, struct in_addr *);
int inet_pton(int, const char *, void *);
const char *inet_ntop(int, const void *, char *, socklen_t);
#ifdef __cplusplus
}
#endif

#endif
