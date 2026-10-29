#ifndef _NETDB_H_
#define _NETDB_H_

#include <sys/socket.h>

/* Application ABI only. These pointers are never sent in an IPC message. */
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

#define AI_PASSIVE       0x0001
#define AI_CANONNAME     0x0002
#define AI_NUMERICHOST   0x0004
#define AI_V4MAPPED      0x0008
#define AI_ALL           0x0010
#define AI_ADDRCONFIG    0x0020
#define AI_NUMERICSERV   0x0400

#define NI_NUMERICHOST   1
#define NI_NUMERICSERV   2
#define NI_NOFQDN        4
#define NI_NAMEREQD      8
#define NI_DGRAM        16
#define NI_MAXHOST      1025
#define NI_MAXSERV      32

#define EAI_BADFLAGS    (-1)
#define EAI_NONAME      (-2)
#define EAI_AGAIN       (-3)
#define EAI_FAIL        (-4)
#define EAI_FAMILY      (-6)
#define EAI_SOCKTYPE    (-7)
#define EAI_SERVICE     (-8)
#define EAI_MEMORY      (-10)
#define EAI_SYSTEM      (-11)
#define EAI_OVERFLOW    (-12)

#ifdef __cplusplus
extern "C" {
#endif
int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
void freeaddrinfo(struct addrinfo *);
int getnameinfo(const struct sockaddr *, socklen_t, char *, socklen_t,
                char *, socklen_t, int);
const char *gai_strerror(int);
#ifdef __cplusplus
}
#endif

#endif
