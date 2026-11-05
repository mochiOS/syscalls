/* Process-local C ownership for the native TLS engine. No ambient network I/O. */
#include <mochios/tls.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LIMIT 65536u
#define SESSIONS 16u
extern int _mochi_tls_core_new(const void *,size_t,const void *,size_t,void **);
extern void _mochi_tls_core_free(void *);
extern int _mochi_tls_core_receive(void *,const void *,size_t);
extern int _mochi_tls_core_write(void *,const void *,size_t);
extern int _mochi_tls_core_status(void *,mochi_tls_status *);
extern int _mochi_tls_core_take(void *,int,void *,size_t,size_t *);
extern int _mochi_tls_core_info(void *,unsigned,size_t,void *,size_t,size_t *);
extern int _mochi_tls_core_close(void *);

typedef struct { uint64_t id; void *core; unsigned char *scratch; } Entry;
static Entry entries[SESSIONS];
static uint64_t next_id = 1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int hooks_ready;
static void acquire(void) { if (pthread_mutex_lock(&lock)!=0) abort(); }
static void release(void) { if (pthread_mutex_unlock(&lock)!=0) abort(); }

static void before_fork(void) { acquire(); }
static void after_parent(void) { release(); }
static void after_child(void)
{
    unsigned i;
    /* Do not run Rust destructors or malloc in an atfork child handler.
     * The inaccessible copied allocations belong to the child's address
     * space until exec/exit. Retire all IDs so no copied nonce can be reused. */
    for (i=0;i<SESSIONS;i++) { entries[i].id=0;entries[i].core=NULL;entries[i].scratch=NULL; }
    release();
}

__attribute__((constructor)) static void initialize(void)
{
    /* Startup-linked archive: register before application threads start. */
    hooks_ready = pthread_atfork(before_fork,after_parent,after_child)==0;
}

static Entry *lookup(uint64_t id)
{
    unsigned i;
    if (!id) return NULL;
    for (i=0;i<SESSIONS;i++) if (entries[i].id==id) return &entries[i];
    return NULL;
}

static void wipe(unsigned char *buffer,size_t size)
{
    volatile unsigned char *p=buffer;
    while (size--) *p++=0;
}

int mochi_tls_available_v1(void) { return hooks_ready; }

int mochi_tls_new_v1(const void *host,size_t host_size,const void *alpn,size_t alpn_size,uint64_t *session)
{
    unsigned i;
    unsigned char hostname[253], protocols[1024];
    void *core=NULL;
    unsigned char *scratch;
    int result;
    if (!session) return MOCHI_TLS_CONFIG;
    *session=0;
    if (!hooks_ready) return MOCHI_TLS_CONFIG;
    if (!host || !host_size || host_size>sizeof(hostname) || alpn_size>sizeof(protocols) || (alpn_size && !alpn)) return MOCHI_TLS_CONFIG;
    memcpy(hostname,host,host_size);
    if (alpn_size) memcpy(protocols,alpn,alpn_size);
    acquire();
    for (i=0;i<SESSIONS;i++) if (!entries[i].id) break;
    if (i==SESSIONS || next_id==UINT64_MAX) { release();return MOCHI_TLS_LIMIT; }
    scratch=malloc(LIMIT);
    if (!scratch) { release();return MOCHI_TLS_LIMIT; }
    result=_mochi_tls_core_new(hostname,host_size,protocols,alpn_size,&core);
    if (result) free(scratch);
    else { entries[i].id=next_id++;entries[i].core=core;entries[i].scratch=scratch;*session=entries[i].id; }
    release();
    return result;
}

static int input(uint64_t session,const void *bytes,size_t size,int plaintext)
{
    int result;
    Entry *entry;
    if ((!bytes && size) || size>(plaintext?16384u:LIMIT)) return MOCHI_TLS_CONFIG;
    acquire();entry=lookup(session);
    if (!entry) result=MOCHI_TLS_STATE;
    else {
        if (size) memcpy(entry->scratch,bytes,size);
        result=plaintext?_mochi_tls_core_write(entry->core,entry->scratch,size):_mochi_tls_core_receive(entry->core,entry->scratch,size);
        if (plaintext) wipe(entry->scratch,size);
    }
    release();return result;
}
int mochi_tls_receive_v1(uint64_t session,const void *bytes,size_t size) { return input(session,bytes,size,0); }
int mochi_tls_write_v1(uint64_t session,const void *bytes,size_t size) { return input(session,bytes,size,1); }

int mochi_tls_status_v1(uint64_t session,mochi_tls_status *status)
{
    mochi_tls_status value;
    Entry *entry;int result;
    if (!status) return MOCHI_TLS_CONFIG;
    acquire();entry=lookup(session);
    result=entry?_mochi_tls_core_status(entry->core,&value):MOCHI_TLS_STATE;
    if (!result) *status=value;
    release();return result;
}

int mochi_tls_take_v1(uint64_t session,int direction,void *buffer,size_t capacity,size_t *written)
{
    Entry *entry;size_t size=0;int result;
    if (!written || (capacity && !buffer) || (direction!=MOCHI_TLS_CIPHERTEXT && direction!=MOCHI_TLS_PLAINTEXT)) return MOCHI_TLS_CONFIG;
    *written=0;
    if (capacity>LIMIT) capacity=LIMIT;
    acquire();entry=lookup(session);
    result=entry?_mochi_tls_core_take(entry->core,direction,entry->scratch,capacity,&size):MOCHI_TLS_STATE;
    if (!result) { if (size) memcpy(buffer,entry->scratch,size);*written=size; }
    if (entry && direction==MOCHI_TLS_PLAINTEXT) wipe(entry->scratch,size);
    release();return result;
}

int mochi_tls_info_v1(uint64_t session,unsigned field,size_t index,void *buffer,size_t capacity,size_t *written)
{
    Entry *entry;size_t size=0;int result;
    if (!written || (capacity && !buffer) || field>MOCHI_TLS_NOT_AFTER || index>=8) return MOCHI_TLS_CONFIG;
    *written=0;
    acquire();entry=lookup(session);
    result=entry?_mochi_tls_core_info(entry->core,field,index,entry->scratch,LIMIT,&size):MOCHI_TLS_STATE;
    if (!result) { *written=size;if (size>capacity) result=MOCHI_TLS_LIMIT;else if (size) memcpy(buffer,entry->scratch,size); }
    release();return result;
}

int mochi_tls_close_notify_v1(uint64_t session)
{
    Entry *entry;int result;
    acquire();entry=lookup(session);
    result=entry?_mochi_tls_core_close(entry->core):MOCHI_TLS_STATE;
    release();return result;
}

int mochi_tls_free_v1(uint64_t session)
{
    Entry *entry;
    acquire();entry=lookup(session);
    if (!entry) { release();return MOCHI_TLS_STATE; }
    _mochi_tls_core_free(entry->core);wipe(entry->scratch,LIMIT);free(entry->scratch);
    entry->core=NULL;entry->scratch=NULL;entry->id=0;
    release();return MOCHI_TLS_OK;
}
