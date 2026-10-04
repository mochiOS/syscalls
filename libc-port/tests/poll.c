#include <poll.h>

int main(void) {
    struct pollfd descriptor = {
        .fd = -1,
        .events = POLLIN,
        .revents = 0,
    };
    return poll(&descriptor, 1, 0) < 0;
}
