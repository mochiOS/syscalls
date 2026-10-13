#include <fcntl.h>
#include <semaphore.h>
#include <stdarg.h>

extern sem_t *__mochios_sem_open(const char *, int, unsigned int, unsigned int);

sem_t *sem_open(const char *name, int options, ...) {
    unsigned int mode = 0, value = 0;
    if (options & O_CREAT) {
        va_list arguments;
        va_start(arguments, options);
        mode = va_arg(arguments, mode_t);
        value = va_arg(arguments, unsigned int);
        va_end(arguments);
    }
    return __mochios_sem_open(name, options, mode, value);
}
