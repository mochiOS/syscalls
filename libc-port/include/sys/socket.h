#ifndef _SYS_SOCKET_H_
#define _SYS_SOCKET_H_

#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>

typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;
struct sockaddr {
  sa_family_t sa_family;
  char sa_data[14];
};

struct msghdr {
  void *msg_name;
  socklen_t msg_namelen;
  struct iovec *msg_iov;
  size_t msg_iovlen;
  void *msg_control;
  size_t msg_controllen;
  int msg_flags;
};

struct cmsghdr {
  size_t cmsg_len;
  int cmsg_level;
  int cmsg_type;
};

#define SCM_RIGHTS 1
#define CMSG_ALIGN(n) (((size_t)(n) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))
#define CMSG_LEN(n) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (size_t)(n))
#define CMSG_SPACE(n) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(n))
#define CMSG_DATA(c) ((unsigned char *)(c) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_FIRSTHDR(m) ((m)->msg_control != NULL && (m)->msg_controllen >= sizeof(struct cmsghdr) \
                         ? (struct cmsghdr *)(m)->msg_control : (struct cmsghdr *)0)

static inline struct cmsghdr *__mochios_cmsg_nxthdr(const struct msghdr *m,
                                                  const struct cmsghdr *c) {
  uintptr_t base = (uintptr_t)m->msg_control;
  uintptr_t current = (uintptr_t)c;
  if (!base || !current || current < base || current - base > m->msg_controllen)
    return (struct cmsghdr *)0;
  size_t remaining = m->msg_controllen - (current - base);
  if (remaining < sizeof(*c) || c->cmsg_len < sizeof(*c) || c->cmsg_len > remaining)
    return (struct cmsghdr *)0;
  size_t step = CMSG_ALIGN(c->cmsg_len);
  if (step < c->cmsg_len || step > remaining || remaining - step < sizeof(*c) ||
      current > UINTPTR_MAX - step)
    return (struct cmsghdr *)0;
  return (struct cmsghdr *)(current + step);
}
#define CMSG_NXTHDR(m, c) __mochios_cmsg_nxthdr((m), (c))

#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_LOCAL AF_UNIX
#define AF_INET 2
#define AF_INET6 10
#define PF_UNSPEC AF_UNSPEC
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
#define SOL_SOCKET 1
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_ACCEPTCONN 30
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
#define MSG_OOB 0x1
#define MSG_PEEK 0x2
#define MSG_CTRUNC 0x8
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_WAITALL 0x100
#define MSG_NOSIGNAL 0x4000
#define MSG_CMSG_CLOEXEC 0x40000000

#ifdef __cplusplus
extern "C" {
#endif
int socketpair(int domain, int type, int protocol, int sv[2]);
int socket(int domain, int type, int protocol);
int bind(int socket, const struct sockaddr *address, socklen_t length);
int listen(int socket, int backlog);
int connect(int socket, const struct sockaddr *address, socklen_t length);
int getsockopt(int socket, int level, int option, void *value, socklen_t *length);
int setsockopt(int socket, int level, int option, const void *value, socklen_t length);
int accept(int socket, struct sockaddr *address, socklen_t *length);
int accept4(int socket, struct sockaddr *address, socklen_t *length, int flags);
int shutdown(int socket, int how);
ssize_t send(int socket, const void *buffer, size_t length, int flags);
ssize_t recv(int socket, void *buffer, size_t length, int flags);
ssize_t recvmsg(int socket, struct msghdr *message, int flags);
ssize_t sendmsg(int socket, const struct msghdr *message, int flags);
ssize_t sendto(int socket, const void *buffer, size_t length, int flags,
               const struct sockaddr *address, socklen_t address_length);
ssize_t recvfrom(int socket, void *buffer, size_t length, int flags,
                 struct sockaddr *address, socklen_t *address_length);
int getsockname(int socket, struct sockaddr *address, socklen_t *length);
int getpeername(int socket, struct sockaddr *address, socklen_t *length);
#ifdef __cplusplus
}
#endif
#endif
