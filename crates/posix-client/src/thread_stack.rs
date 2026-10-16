//! Layout policy for downward-growing POSIX thread stacks.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub guard_size: usize,
    pub usable_size: usize,
    pub mapping_size: usize,
}

impl Layout {
    /// The guard is additional space, never taken out of the usable stack.
    /// The caller reserves the whole range without access, then enables only
    /// the usable suffix. Caller-supplied stacks do not use this layout.
    pub const fn new(stack_size: usize, guard_size: usize, page_size: usize) -> Option<Self> {
        if stack_size == 0 || !page_size.is_power_of_two() {
            return None;
        }
        let Some(usable_size) = round_up(stack_size, page_size) else {
            return None;
        };
        let Some(guard_size) = round_up(guard_size, page_size) else {
            return None;
        };
        let Some(mapping_size) = usable_size.checked_add(guard_size) else {
            return None;
        };
        Some(Self {
            guard_size,
            usable_size,
            mapping_size,
        })
    }
}

const fn round_up(value: usize, alignment: usize) -> Option<usize> {
    match value.checked_add(alignment - 1) {
        Some(value) => Some(value & !(alignment - 1)),
        None => None,
    }
}
