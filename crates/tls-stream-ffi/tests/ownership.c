/* Host ABI/ownership fixture; does not execute mochiOS binaries. */
#include <mochios/tls.h>
#include <assert.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void)
{
    uint64_t handles[16],next=0;mochi_tls_status state;size_t count;unsigned char bytes[1024];unsigned i;
    const unsigned char duplicate[]={2,'h','2',2,'h','2'};
    assert(sizeof(state)==16);assert(mochi_tls_available_v1());
    assert(mochi_tls_new_v1("tls.test.mochios",16,duplicate,sizeof(duplicate),&next)==MOCHI_TLS_CONFIG);
    assert(next==0);
    for(i=0;i<16;i++) assert(mochi_tls_new_v1("tls.test.mochios",16,NULL,0,&handles[i])==0);
    assert(mochi_tls_new_v1("tls.test.mochios",16,NULL,0,&next)==MOCHI_TLS_LIMIT && !next);
    assert(mochi_tls_status_v1(handles[0],&state)==0 && state.state==MOCHI_TLS_HANDSHAKING && state.transmit_pending>0);
    { unsigned before=state.transmit_pending;
      assert(mochi_tls_take_v1(handles[0],MOCHI_TLS_CIPHERTEXT,bytes,1,&count)==0 && count==1 && bytes[0]==0x16);
      assert(mochi_tls_status_v1(handles[0],&state)==0 && state.transmit_pending==before-1); }
    assert(mochi_tls_write_v1(handles[0],"no",2)==MOCHI_TLS_STATE);
    assert(mochi_tls_status_v1(handles[0],&state)==0 && state.state==MOCHI_TLS_HANDSHAKING);
    assert(mochi_tls_receive_v1(handles[0],NULL,65537)==MOCHI_TLS_CONFIG);
    { pid_t child=fork();int status;
      assert(child>=0);
      if(!child) {uint64_t fresh=0;assert(mochi_tls_status_v1(handles[0],&state)==MOCHI_TLS_STATE);
        assert(mochi_tls_new_v1("tls.test.mochios",16,NULL,0,&fresh)==0 && fresh!=handles[0]);
        assert(mochi_tls_free_v1(fresh)==0);_exit(0);}
      assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
      assert(mochi_tls_status_v1(handles[0],&state)==0); }
    for(i=0;i<16;i++) assert(mochi_tls_free_v1(handles[i])==0);
    assert(mochi_tls_free_v1(handles[0])==MOCHI_TLS_STATE);
    assert(mochi_tls_new_v1("tls.test.mochios",16,NULL,0,&next)==0 && next!=handles[0]);
    assert(mochi_tls_free_v1(next)==0);
    return 0;
}
