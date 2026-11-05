#ifndef MOCHIOS_TLS_H
#define MOCHIOS_TLS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Transport-independent TLS 1.3. No function opens a socket or replaces trust.
 * Return 0 on success, a MOCHI_TLS_* error otherwise. Calls are serialized
 * internally. These APIs are not async-signal-safe. Buffers must remain valid
 * throughout each call. Fork invalidates all inherited session handles. */
enum { MOCHI_TLS_OK=0, MOCHI_TLS_NAME=1, MOCHI_TLS_CONFIG=2,
 MOCHI_TLS_RANDOM=3, MOCHI_TLS_TIME=4, MOCHI_TLS_CERTIFICATE=5,
 MOCHI_TLS_HOSTNAME=6, MOCHI_TLS_CHAIN_DEPTH=7, MOCHI_TLS_CERT_SIZE=8,
 MOCHI_TLS_CHAIN_SIZE=9, MOCHI_TLS_AUTH=10, MOCHI_TLS_LIMIT=11,
 MOCHI_TLS_PROTOCOL=12, MOCHI_TLS_ALERT=13, MOCHI_TLS_STATE=14 };
enum { MOCHI_TLS_HANDSHAKING=1, MOCHI_TLS_ESTABLISHED=2,
 MOCHI_TLS_PEER_CLOSED=3, MOCHI_TLS_CLOSING=4, MOCHI_TLS_CLOSED=5, MOCHI_TLS_FAILED=6 };
enum { MOCHI_TLS_CIPHERTEXT=0, MOCHI_TLS_PLAINTEXT=1 };
enum { MOCHI_TLS_ALPN=0, MOCHI_TLS_CERT_DER=1, MOCHI_TLS_SUBJECT=2,
 MOCHI_TLS_ISSUER=3, MOCHI_TLS_NOT_BEFORE=4, MOCHI_TLS_NOT_AFTER=5 };
typedef struct { uint32_t state, receive_pending, transmit_pending; uint16_t protocol, cipher; } mochi_tls_status;
/* Whether the archive initialized its fork-safety hooks successfully. */
int mochi_tls_available_v1(void);
/* Create a session. ALPN is a sequence of one-byte lengths followed by protocol
 * bytes (max 16 names / 1024 bytes); no offer is represented by size zero.
 * Hostnames must be DNS names. On failure, *session is zero. */
int mochi_tls_new_v1(const void *hostname,size_t hostname_size,const void *alpn,size_t alpn_size,uint64_t *session);
/* Feed encrypted bytes from the authorized base stream, at most 64 KiB/call. */
int mochi_tls_receive_v1(uint64_t session,const void *bytes,size_t size);
/* Queue at most 16 KiB of application plaintext for authenticated encryption. */
int mochi_tls_write_v1(uint64_t session,const void *bytes,size_t size);
/* Advance protocol state and obtain exact pending-byte counts. */
int mochi_tls_status_v1(uint64_t session,mochi_tls_status *status);
/* Consume queued bytes in one direction. Partial drains are supported. */
int mochi_tls_take_v1(uint64_t session,int direction,void *buffer,size_t capacity,size_t *written);
/* Read immutable verified peer metadata. DER index selects a chain member;
 * timestamps are native uint64_t Unix seconds. Missing index returns STATE.
 * LIMIT reports the required size through *written without consuming data. */
int mochi_tls_info_v1(uint64_t session,unsigned field,size_t index,void *buffer,size_t capacity,size_t *written);
/* Queue close_notify; drain CIPHERTEXT before closing the transport. */
int mochi_tls_close_notify_v1(uint64_t session);
/* Release a live handle. Stale/inherited handles return STATE. */
int mochi_tls_free_v1(uint64_t session);
#ifdef __cplusplus
}
#endif
#endif
