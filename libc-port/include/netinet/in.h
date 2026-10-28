#ifndef _NETINET_IN_H_
#define _NETINET_IN_H_

#include <stdint.h>
#include <sys/socket.h>

typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;
struct in_addr { in_addr_t s_addr; };
struct sockaddr_in {
  sa_family_t sin_family;
  in_port_t sin_port;
  struct in_addr sin_addr;
  unsigned char sin_zero[8];
};
struct in6_addr {
  union {
    uint8_t __u6_addr8[16];
    uint16_t __u6_addr16[8];
    uint32_t __u6_addr32[4];
  } __in6_u;
};
#define s6_addr __in6_u.__u6_addr8
#define s6_addr16 __in6_u.__u6_addr16
#define s6_addr32 __in6_u.__u6_addr32
struct sockaddr_in6 {
  sa_family_t sin6_family;
  in_port_t sin6_port;
  uint32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  uint32_t sin6_scope_id;
};

#define IPPROTO_IP 0
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define INADDR_ANY ((in_addr_t)0x00000000)
#define INADDR_LOOPBACK ((in_addr_t)0x7f000001)
#define INADDR_BROADCAST ((in_addr_t)0xffffffff)
#define INADDR_NONE INADDR_BROADCAST
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46
#define IN6ADDR_ANY_INIT {{{0}}}
#define IN6ADDR_LOOPBACK_INIT                                                  \
  {                                                                            \
    {                                                                          \
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }                       \
    }                                                                          \
  }

static inline int __mochi_in6_zero_prefix(const struct in6_addr *address,
                                          unsigned count) {
  for (unsigned index = 0; index < count; ++index)
    if (address->s6_addr[index])
      return 0;
  return 1;
}
static inline int __mochi_in6_unspecified(const struct in6_addr *address) {
  return __mochi_in6_zero_prefix(address, 16);
}
static inline int __mochi_in6_loopback(const struct in6_addr *address) {
  return __mochi_in6_zero_prefix(address, 15) && address->s6_addr[15] == 1;
}
static inline int __mochi_in6_v4mapped(const struct in6_addr *address) {
  return __mochi_in6_zero_prefix(address, 10) && address->s6_addr[10] == 0xff &&
         address->s6_addr[11] == 0xff;
}
static inline int __mochi_in6_v4compat(const struct in6_addr *address) {
  return __mochi_in6_zero_prefix(address, 12) &&
         !__mochi_in6_unspecified(address) && !__mochi_in6_loopback(address);
}
static inline int __mochi_in6_linklocal(const struct in6_addr *address) {
  return address->s6_addr[0] == 0xfe && (address->s6_addr[1] & 0xc0) == 0x80;
}
static inline int __mochi_in6_sitelocal(const struct in6_addr *address) {
  return address->s6_addr[0] == 0xfe && (address->s6_addr[1] & 0xc0) == 0xc0;
}
static inline int __mochi_in6_multicast(const struct in6_addr *address) {
  return address->s6_addr[0] == 0xff;
}
static inline int __mochi_in6_multicast_scope(const struct in6_addr *address,
                                              unsigned scope) {
  return __mochi_in6_multicast(address) &&
         (address->s6_addr[1] & 0x0f) == scope;
}
#define IN6_IS_ADDR_UNSPECIFIED(a) __mochi_in6_unspecified((a))
#define IN6_IS_ADDR_LOOPBACK(a) __mochi_in6_loopback((a))
#define IN6_IS_ADDR_V4MAPPED(a) __mochi_in6_v4mapped((a))
#define IN6_IS_ADDR_V4COMPAT(a) __mochi_in6_v4compat((a))
#define IN6_IS_ADDR_LINKLOCAL(a) __mochi_in6_linklocal((a))
#define IN6_IS_ADDR_SITELOCAL(a) __mochi_in6_sitelocal((a))
#define IN6_IS_ADDR_MULTICAST(a) __mochi_in6_multicast((a))
#define IN6_IS_ADDR_MC_NODELOCAL(a) __mochi_in6_multicast_scope((a), 1)
#define IN6_IS_ADDR_MC_LINKLOCAL(a) __mochi_in6_multicast_scope((a), 2)
#define IN6_IS_ADDR_MC_SITELOCAL(a) __mochi_in6_multicast_scope((a), 5)
#define IN6_IS_ADDR_MC_ORGLOCAL(a) __mochi_in6_multicast_scope((a), 8)
#define IN6_IS_ADDR_MC_GLOBAL(a) __mochi_in6_multicast_scope((a), 14)

#ifdef __cplusplus
extern "C" {
#endif
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
uint32_t htonl(uint32_t);
uint16_t htons(uint16_t);
uint32_t ntohl(uint32_t);
uint16_t ntohs(uint16_t);
#ifdef __cplusplus
}
#endif

#endif
