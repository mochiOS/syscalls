// The current x86_64-elf newlib ABI uses unsigned short for uid_t and gid_t.
pub type Id = u16;

/// A failed or unrepresentable identity must never become UID/GID zero.
/// Leave errno unchanged on success, and preserve the original query error.
pub fn finish(result: Result<u32, i32>, overflow: i32, set_errno: impl FnOnce(i32)) -> Id {
    match result.and_then(|id| Id::try_from(id).map_err(|_| overflow)) {
        Ok(id) => id,
        Err(error) => {
            set_errno(error);
            Id::MAX
        }
    }
}
