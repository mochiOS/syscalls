#ifndef _MOCHI_EXECUTABLE_H
#define _MOCHI_EXECUTABLE_H
#include <stdint.h>
#include <spawn.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Select an own signed executable_export with alias="", name="helper", or
 * a per-binary executable_dependency with alias="engine-helper", name="".
 * No filesystem paths, environment identities or undeclared packages are
 * accepted. Requires native startup authority and process.spawn. Returns an
 * owned opaque native code reference, or 0 with errno set. This is not an FD.
 * The broker captures the root and signed library closure. A later package
 * replacement cannot supply new bytes through this reference. Fork children
 * in the same measured image may use it; unrelated images may not. */
uint32_t mochi_executable_open(const char *alias, const char *name);
/* Replace the calling image using that captured code and explicit argv/envp.
 * Never returns on success; returns -1 with errno on failure. Keeps the
 * existing POSIX FD/CLOEXEC behavior. Child capabilities cannot exceed the
 * caller's permissions; user-consent checks remain in force. No ambient
 * library search fallback or broad filesystem grant is performed. Requires
 * system.random.read (as required by ordinary exec) and the matching updated
 * OS brokers and runtime. */
int mochi_executable_execve(uint32_t reference, const char *const argv[], const char *const envp[]);
/* A successfully exec'd, POSIX-registered child. process is an owned native
 * ProcessHandle, not a PID/FD; close it with native HandleClose after use. */
struct mochi_spawned_process { int32_t pid; uint32_t process; };
/* Spawn using normal POSIX attributes/file actions and the captured code.
 * Returns 0 only after a committed image is confirmed; otherwise returns a
 * positive errno value, like posix_spawn. output is unspecified on failure.
 * Successful output transfers ownership of the exact native child reference.
 * No application pre_exec callback or PID-based process lookup is needed. */
int mochi_executable_spawn(struct mochi_spawned_process *output,
    uint32_t reference, const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attributes, const char *const argv[],
    const char *const envp[]);
/* Release one owned reference. Do not concurrently close a reference in use.
 * Captured code remains alive while another owned reference uses it. */
int mochi_executable_close(uint32_t reference);
#ifdef __cplusplus
}
#endif
#endif
