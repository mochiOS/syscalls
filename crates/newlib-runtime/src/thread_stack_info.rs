//! Resolve runtime-owned stack metadata; unknown native stacks fail closed.
use super::{EINVAL, ENOTSUP, PTHREAD_STACK_MIN, c_int};

pub(super) struct Observed {
    pub base: usize,
    pub reservation_size: usize,
    pub guard_size: usize,
    pub owned: bool,
    pub initial: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Stack {
    pub base: usize,
    pub size: usize,
    pub guard_size: usize,
}

/// Never infer an initial stack from a missing worker registration. Kernel
/// snapshots are requested only for the explicitly registered initial thread.
/// Main-stack growth is an observation, not an additional mapping or grant.
pub(super) fn resolve(
    observed: Observed,
    initial: impl FnOnce() -> Result<mnu_abi::ProcessInitialStackInfo, c_int>,
) -> Result<Stack, c_int> {
    if observed.base != 0 || observed.reservation_size != 0 {
        let guard = if observed.owned {
            observed.guard_size
        } else {
            0
        };
        if observed.base == 0
            || observed.reservation_size <= guard
            || (!observed.owned && observed.guard_size != 0)
            || observed
                .base
                .checked_add(observed.reservation_size)
                .is_none()
        {
            return Err(EINVAL);
        }
        let size = observed.reservation_size - guard;
        if size < PTHREAD_STACK_MIN {
            return Err(EINVAL);
        }
        return Ok(Stack {
            base: observed.base + guard,
            size,
            guard_size: guard,
        });
    }
    if !observed.initial {
        return Err(ENOTSUP);
    }
    let info = initial()?;
    if info.lower_bound == 0
        || info.lower_bound > info.committed_lower_bound
        || info.committed_lower_bound >= info.upper_bound
    {
        return Err(EINVAL);
    }
    let base = usize::try_from(info.lower_bound).map_err(|_| EINVAL)?;
    let size = usize::try_from(info.upper_bound - info.lower_bound).map_err(|_| EINVAL)?;
    if size < PTHREAD_STACK_MIN || base.checked_add(size).is_none() {
        return Err(EINVAL);
    }
    Ok(Stack {
        base,
        size,
        guard_size: 0,
    })
}
