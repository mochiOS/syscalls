#ifndef _SYS_SOCKET_H_
#define _SYS_SOCKET_H_

#include <sys/types.h>

typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;
struct sockaddr {
  sa_family_t sa_family;
  char sa_data[14];
};

#define AF_UNIX 1
#define AF_LOCAL AF_UNIX
#define AF_INET 2
#define AF_INET6 10
#define PF_UNIX AF_UNIX
#define PF_LOCAL AF_LOCAL
#define PF_INET AF_INET
#define PF_INET6 AF_INET6
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_SEQPACKET 5
#define SOCK_NONBLOCK 0x800
#define SOCK_CLOEXEC 0x80000
#define SOMAXCONN 128
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
#define MSG_OOB 0x1
#define MSG_PEEK 0x2
#define MSG_DONTWAIT 0x40
#define MSG_WAITALL 0x100
#define MSG_NOSIGNAL 0x4000

#ifdef __cplusplus
extern "C" {
#endif
int socketpair(int domain, int type, int protocol, int sv[2]);
int socket(int domain, int type, int protocol);
int bind(int socket, const struct sockaddr *address, socklen_t length);
int listen(int socket, int backlog);
int shutdown(int socket, int how);
ssize_t send(int socket, const void *buffer, size_t length, int flags);
ssize_t recv(int socket, void *buffer, size_t length, int flags);
int getsockname(int socket, struct sockaddr *address, socklen_t *length);
int getpeername(int socket, struct sockaddr *address, socklen_t *length);
#ifdef __cplusplus
}
#endif
#endif
