#ifndef _MOCHIOS_ARPA_NAMESER_H
#define _MOCHIOS_ARPA_NAMESER_H
#include <stdint.h>
/* Historical resolver header view. Multibyte fields remain network order. */
typedef struct {
    uint16_t id;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char rd:1, tc:1, aa:1, opcode:4, qr:1;
    unsigned char rcode:4, cd:1, ad:1, unused:1, ra:1;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned char qr:1, opcode:4, aa:1, tc:1, rd:1;
    unsigned char ra:1, unused:1, ad:1, cd:1, rcode:4;
#else
#error Unsupported byte order for DNS HEADER
#endif
    uint16_t qdcount, ancount, nscount, arcount;
} HEADER;
#define NS_GET16(value, cursor) do { \
    const unsigned char *_ns_p = (const unsigned char *)(cursor); \
    (value) = ((uint16_t)_ns_p[0] << 8) | (uint16_t)_ns_p[1]; \
    (cursor) += 2; \
} while (0)
#define NS_GET32(value, cursor) do { \
    const unsigned char *_ns_p = (const unsigned char *)(cursor); \
    (value) = ((uint32_t)_ns_p[0] << 24) | ((uint32_t)_ns_p[1] << 16) \
            | ((uint32_t)_ns_p[2] << 8) | (uint32_t)_ns_p[3]; \
    (cursor) += 4; \
} while (0)
/* The caller must validate bounds before using these compatibility macros. */
#define GETSHORT NS_GET16
#define GETLONG NS_GET32
/* DNS wire constants supported by the scoped resolver API. */
#define NS_PACKETSZ 512
#define NS_MAXDNAME 1025
#define NS_MAXCDNAME 255
#define NS_MAXLABEL 63
#define NS_HFIXEDSZ 12
#define NS_QFIXEDSZ 4
#define NS_RRFIXEDSZ 10
#define NS_INT16SZ 2
#define NS_INT32SZ 4
#define C_IN 1
#define T_A 1
#define T_NS 2
#define T_CNAME 5
#define T_SOA 6
#define T_PTR 12
#define T_MX 15
#define T_TXT 16
#define T_AAAA 28
#define T_SRV 33
typedef enum { ns_c_in = C_IN } ns_class;
typedef enum {
    ns_t_a = T_A, ns_t_ns = T_NS, ns_t_cname = T_CNAME,
    ns_t_soa = T_SOA, ns_t_ptr = T_PTR, ns_t_mx = T_MX,
    ns_t_txt = T_TXT, ns_t_aaaa = T_AAAA, ns_t_srv = T_SRV
} ns_type;
#endif
