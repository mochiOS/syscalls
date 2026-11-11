#ifndef _MOCHI_BUNDLE_H
#define _MOCHI_BUNDLE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Use "" for the main application's signed resources, or an explicitly
 * selected resource_dependency alias. No absolute package paths are accepted.
 * Each function requires launcher-installed bundle authority, never environment
 * metadata. Check returns 0 on success, -1 with errno on failure. */
int mochi_bundle_check(const char *alias);
/* Open one declared logical file as an owned O_RDONLY|O_CLOEXEC descriptor.
 * Close with close(). Contents are captured and checked against the signed
 * startup manifest. No fallback to a newly installed package version occurs. */
int mochi_bundle_open(const char *alias, const char *name);
/* Create an immutable process-local directory view and write its NUL-terminated
 * absolute path. capacity must be >=128. Returns a nonzero lifetime token, or
 * zero with errno set. Ordinary open/stat/opendir/read-only mmap use this view.
 * The path is valid until directory_close(token); open files retain their own
 * contents. Paths/tokens cannot be transferred to another process or serialized
 * for reuse. Pass explicit read-only file references to a child instead.
 * Views are invalid in a fork child and do not survive exec. Max 64 live views.
 * An empty main resource set is a valid directory. No symlink or ambient fallback exists. */
uint64_t mochi_bundle_directory_open(const char *alias, char *path, size_t capacity);
/* Retire one owned lifetime token. Repeated or stale tokens fail with errno.
 * Previously returned paths never refer to a subsequently created directory. */
int mochi_bundle_directory_close(uint64_t token);
#ifdef __cplusplus
}
#endif
#endif
