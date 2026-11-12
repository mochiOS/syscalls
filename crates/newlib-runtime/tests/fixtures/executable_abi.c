/* Compile this with the native SDK; no host target can establish this ABI. */
#if !defined(__mochios__)
#error Native mochiOS target required
#endif
#include <mochi/executable.h>
#include <stddef.h>
_Static_assert(sizeof(struct mochi_spawned_process) == 8, "spawn result size");
_Static_assert(offsetof(struct mochi_spawned_process, process) == 4, "spawn handle offset");
_Static_assert(sizeof(posix_spawn_file_actions_t) == sizeof(void *), "native actions are opaque references");
typedef uint32_t (*open_fn)(const char *, const char *);
typedef int (*exec_fn)(uint32_t, const char *const *, const char *const *);
typedef int (*spawn_fn)(struct mochi_spawned_process *, uint32_t, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, const char *const *, const char *const *);
typedef int (*close_fn)(uint32_t);
#define MATCH(name, type) _Static_assert(_Generic(&(name), type: 1, default: 0), #name " ABI")
MATCH(mochi_executable_open, open_fn);
MATCH(mochi_executable_execve, exec_fn);
MATCH(mochi_executable_spawn, spawn_fn);
MATCH(mochi_executable_close, close_fn);
