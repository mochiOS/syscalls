#ifndef _MOCHIOS_DLFCN_H
#define _MOCHIOS_DLFCN_H

#define RTLD_LAZY     0x00001
#define RTLD_NOW      0x00002
#define RTLD_NOLOAD   0x00004
#define RTLD_DEEPBIND 0x00008
#define RTLD_GLOBAL   0x00100
#define RTLD_LOCAL    0
#define RTLD_NODELETE 0x01000
#define RTLD_DEFAULT  ((void *)0)
#define RTLD_NEXT     ((void *)-1L)

#ifdef __cplusplus
extern "C" {
#endif
void *dlopen(const char *, int);
void *dlsym(void *, const char *);
int dlclose(void *);
char *dlerror(void);
#ifdef __cplusplus
}
#endif
#endif
