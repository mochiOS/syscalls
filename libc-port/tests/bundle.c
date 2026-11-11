/* Compile/link ABI probe. Runtime use requires a normally launched signed
 * application with appicon.png recorded in its resource file bindings. */
#include <mochi/bundle.h>
#include <unistd.h>
int main(void) {
    char path[128];
    if (mochi_bundle_check("")) return 1;
    int fd = mochi_bundle_open("", "appicon.png");
    if (fd >= 0) close(fd);
    uint64_t view = mochi_bundle_directory_open("", path, sizeof path);
    if (view) return mochi_bundle_directory_close(view);
    return 0;
}
