#include <stddef.h>
#include <pty.h>
#include <termios.h>

_Static_assert(sizeof(struct termios) == 56, "unexpected mochiOS termios ABI");
_Static_assert(offsetof(struct termios, c_cc) == 16, "unexpected c_cc offset");
_Static_assert(offsetof(struct termios, c_ispeed) == 48, "unexpected c_ispeed offset");

int main(void) {
    struct termios attributes = {0};
    cfmakeraw(&attributes);
    if (cfsetspeed(&attributes, B38400) != 0) {
        return 1;
    }
    (void)cfgetispeed(&attributes);
    (void)cfgetospeed(&attributes);
    (void)tcgetattr(-1, &attributes);
    (void)tcsetattr(-1, TCSANOW, &attributes);
    (void)tcdrain(-1);
    (void)tcflush(-1, TCIOFLUSH);
    return openpty(0, 0, 0, &attributes, 0) == 0;
}
