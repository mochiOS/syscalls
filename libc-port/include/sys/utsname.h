#ifndef _SYS_UTSNAME_H_
#define _SYS_UTSNAME_H_

#ifdef __cplusplus
extern "C" {
#endif

#define _MOCHIOS_UTSNAME_LENGTH 256
struct utsname {
    char sysname[_MOCHIOS_UTSNAME_LENGTH];
    char nodename[_MOCHIOS_UTSNAME_LENGTH];
    char release[_MOCHIOS_UTSNAME_LENGTH];
    char version[_MOCHIOS_UTSNAME_LENGTH];
    char machine[_MOCHIOS_UTSNAME_LENGTH];
};
int uname(struct utsname *);

#ifdef __cplusplus
}
#endif
#endif
