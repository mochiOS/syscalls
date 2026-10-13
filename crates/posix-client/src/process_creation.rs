//! Transaction ordering for user-space policy around native stopped creation.

/// Creates a scheduling-suspended object, installs user-space state, resolves
/// identity while stopped, then resumes it. On any post-creation failure the
/// exact creation reference is passed to `rollback`, even when termination
/// fails. The callback must retain that reference until cleanup is confirmed.
/// No PID lookup, reference close, or policy bypass occurs in this helper.
pub fn create_with_rollback<H: Copy, E>(
    create: impl FnOnce() -> Result<H, E>,
    setup: impl FnOnce(H) -> Result<(), E>,
    identify: impl FnOnce(H) -> Result<u64, E>,
    resume: impl FnOnce(H) -> Result<(), E>,
    mut terminate: impl FnMut(H),
    rollback: impl FnOnce(H),
) -> Result<(H, u64), E> {
    let handle = create()?;
    let result = (|| {
        setup(handle)?;
        let identity = identify(handle)?;
        resume(handle)?;
        Ok(identity)
    })();
    match result {
        Ok(identity) => Ok((handle, identity)),
        Err(error) => {
            terminate(handle);
            rollback(handle);
            Err(error)
        }
    }
}
