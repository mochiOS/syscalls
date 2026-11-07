// The current x86_64-elf newlib ABI uses unsigned short for uid_t and gid_t.
pub type Id = u16;

/// Widen `(uid_t)-1` / `(gid_t)-1` to the wire protocol's unchanged sentinel.
pub fn update_id(id: Id) -> u32 {
    if id == Id::MAX {
        u32::MAX
    } else {
        u32::from(id)
    }
}

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

/// Permit environment access only after a known non-secure image start and a
/// successful current-credential query. Invalid/unrepresentable IDs fail closed.
pub(super) fn allows_environment(initial_secure: Option<bool>, ids: Option<[u32; 4]>) -> bool {
    if initial_secure != Some(false) {
        return false;
    }
    let Some([uid, euid, gid, egid]) = ids else {
        return false;
    };
    [uid, euid, gid, egid]
        .iter()
        .all(|id| *id < u32::from(Id::MAX))
        && uid == euid
        && gid == egid
}

#[cfg(test)]
mod secure_environment_tests {
    use super::*;
    #[test]
    fn secure_unknown_and_failed_queries_are_denied() {
        let ids = Some([1000, 1000, 1000, 1000]);
        assert!(allows_environment(Some(false), ids));
        assert!(!allows_environment(Some(true), ids));
        assert!(!allows_environment(None, ids));
        assert!(!allows_environment(Some(false), None));
    }
    #[test]
    fn each_privilege_mismatch_and_unrepresentable_id_is_denied() {
        for index in 0..4 {
            let mut ids = [1000; 4];
            ids[index] = 0;
            assert!(!allows_environment(Some(false), Some(ids)));
            for invalid in [u32::from(Id::MAX), u32::from(Id::MAX) + 1, u32::MAX] {
                let mut ids = [1000; 4];
                ids[index] = invalid;
                assert!(!allows_environment(Some(false), Some(ids)));
            }
        }
        assert!(allows_environment(Some(false), Some([0; 4])));
    }
}
