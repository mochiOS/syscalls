#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int descriptors[2];
    char byte;

    if (pipe2(descriptors, O_NONBLOCK) != 0)
        return 1;
    if ((fcntl(descriptors[0], F_GETFL) & O_NONBLOCK) == 0)
        return 2;
    if (read(descriptors[0], &byte, 1) != -1 || errno != EAGAIN)
        return 3;
    if (fcntl(descriptors[0], F_SETFL, 0) != 0)
        return 4;
    if ((fcntl(descriptors[0], F_GETFL) & O_NONBLOCK) != 0)
        return 5;
    return 0;
}
