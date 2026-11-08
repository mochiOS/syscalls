//! Observe a caught handler, not merely a notification or an epoch change.
pub(super) fn wait<E>(
    captured: u64,
    generation: impl Fn() -> u64,
    mut epoch: impl FnMut() -> Result<u64, E>,
    mut drain: impl FnMut() -> Result<(), E>,
    mut notification: impl FnMut(u64) -> Result<(), E>,
) -> Result<(), E> {
    loop {
        if generation() != captured {
            return Ok(());
        }
        // Snapshot before draining. The service checks this epoch when it
        // admits a retained wait, closing the drain-to-sleep arrival race.
        let observed = epoch()?;
        drain()?;
        if generation() != captured {
            return Ok(());
        }
        notification(observed)?;
        drain()?;
    }
}
