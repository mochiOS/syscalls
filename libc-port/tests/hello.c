#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *buffer = malloc(128);

    if (buffer == NULL) {
        fputs("malloc failed\n", stderr);
        return 1;
    }

    snprintf(buffer, 128, "hello from mochiOS, argc=%d\n", argc);
    fputs(buffer, stdout);
    free(buffer);

    (void)argv;
    return 0;
}
