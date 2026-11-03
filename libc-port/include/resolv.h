#ifndef _MOCHIOS_RESOLV_H
#define _MOCHIOS_RESOLV_H
#include <arpa/nameser.h>
#include <netdb.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Uses the delegated native DNS service. Only IN and explicitly supported
 * record kinds are accepted. No arbitrary DNS server override is provided.
 * The return value is the complete required reply size; when it exceeds the
 * buffer capacity, TC is set in the copied prefix. Resize before parsing.
 * Native snapshot replies have TTL 0 and make no DNSSEC assertion. */
int res_query(const char *, int, int, unsigned char *, int);
/* Returns compressed input bytes consumed; writes a NUL-terminated DNS name.
 * A root name expands to an empty string. Returns -1 on malformed input,
 * inaccessible memory or insufficient destination space. */
int dn_expand(const unsigned char *, const unsigned char *,
              const unsigned char *, char *, int);
#ifdef __cplusplus
}
#endif
#endif
