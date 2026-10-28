//! Dependency-ordered lifecycle planning, separate from BFS symbol lookup.
//! Plans describe relocated arrays; they do not call code or install mappings.
use super::super::{Error, add, lifecycle::Array};
use super::Scope;
mod image;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Function {
        object: usize,
        address: u64,
    },
    Array {
        object: usize,
        address: u64,
        count: u64,
        reverse: bool,
    },
}

/// A plan for the immutable captured scope, not a record of executed calls.
/// The eventual runtime must arrange once-only initialization/finalization,
/// read array elements after relocation, and retain mappings until teardown.
pub struct Lifecycle<'plan, 'scope, 'image> {
    scope: &'plan Scope<'scope, 'image>,
    order: &'plan [usize],
}

impl<'scope, 'image> Scope<'scope, 'image> {
    /// Required number of usize scratch words for iterative DFS. No recursion,
    /// allocation or process-global state is needed, even with cyclic graphs.
    pub fn lifecycle_scratch_len(&self) -> Result<usize, Error> {
        self.objects.len().checked_mul(4).ok_or(Error::Overflow)
    }

    pub fn lifecycle<'plan>(
        &'plan self,
        scratch: &'plan mut [usize],
    ) -> Result<Lifecycle<'plan, 'scope, 'image>, Error> {
        if scratch.len() < self.lifecycle_scratch_len()? {
            return Err(Error::BufferTooSmall);
        }
        // Preinitialization belongs to the executable, never a dependency.
        if self.objects[1..]
            .iter()
            .any(|object| object.image.lifecycle.preinit.count != 0)
        {
            return Err(Error::Unsupported);
        }
        let count = self.objects.len();
        let (states, tail) = scratch.split_at_mut(count);
        let (stack, tail) = tail.split_at_mut(count);
        let (next, order) = tail.split_at_mut(count);
        states.fill(0);
        let mut depth = 1;
        let mut written = 0;
        stack[0] = 0;
        next[0] = 0;
        states[0] = 1;
        while depth != 0 {
            let object = stack[depth - 1];
            let mut dependency = None;
            let mut ordinal = 0;
            self.objects[object].image.dependencies(|name| {
                if ordinal == next[depth - 1] {
                    dependency = Some(
                        self.objects
                            .iter()
                            .position(|candidate| candidate.name == name)
                            .ok_or(Error::Invalid)?,
                    );
                }
                ordinal += 1;
                Ok(())
            })?;
            if let Some(dependency) = dependency {
                next[depth - 1] += 1;
                if states[dependency] == 0 {
                    states[dependency] = 1;
                    stack[depth] = dependency;
                    next[depth] = 0;
                    depth += 1;
                }
                // A back edge is already on the stack. Cycle ordering is not
                // specified by the ABI; choose deterministic DFS postorder.
            } else {
                states[object] = 2;
                order[written] = object;
                written += 1;
                depth -= 1;
            }
        }
        if written != count {
            return Err(Error::Invalid);
        }
        Ok(Lifecycle {
            scope: self,
            order: &order[..written],
        })
    }
}

impl Lifecycle<'_, '_, '_> {
    pub fn order(&self) -> &[usize] {
        self.order
    }

    fn array(
        &self,
        object: usize,
        array: Array,
        reverse: bool,
        emit: &mut impl FnMut(Step),
    ) -> Result<(), Error> {
        if array.count != 0 {
            emit(Step::Array {
                object,
                address: add(array.address, self.scope.objects[object].bias)?,
                count: array.count,
                reverse,
            });
        }
        Ok(())
    }

    fn function(
        &self,
        object: usize,
        address: u64,
        emit: &mut impl FnMut(Step),
    ) -> Result<(), Error> {
        if address != 0 {
            emit(Step::Function {
                object,
                address: add(address, self.scope.objects[object].bias)?,
            });
        }
        Ok(())
    }

    /// Preinit for object zero, then dependencies before their dependents.
    /// Within one object, DT_INIT precedes the forward DT_INIT_ARRAY.
    pub fn initializers(&self, mut emit: impl FnMut(Step)) -> Result<(), Error> {
        self.array(
            0,
            self.scope.objects[0].image.lifecycle.preinit,
            false,
            &mut emit,
        )?;
        for &object in self.order {
            let metadata = self.scope.objects[object].image.lifecycle;
            self.function(object, metadata.init, &mut emit)?;
            self.array(object, metadata.initialize, false, &mut emit)?;
        }
        Ok(())
    }

    /// Dependents precede dependencies. Reverse DT_FINI_ARRAY before DT_FINI.
    pub fn finalizers(&self, mut emit: impl FnMut(Step)) -> Result<(), Error> {
        for &object in self.order.iter().rev() {
            let metadata = self.scope.objects[object].image.lifecycle;
            self.array(object, metadata.finalize, true, &mut emit)?;
            self.function(object, metadata.fini, &mut emit)?;
        }
        Ok(())
    }

    /// Array entries can resolve to functions in other captured objects. Check
    /// the relocated value before invoking it; an array's own readable extent
    /// does not prove that any of its contents designate executable code.
    pub fn is_callable(&self, address: u64) -> bool {
        self.scope.objects.iter().any(|object| {
            address.checked_sub(object.bias).is_some_and(|relative| {
                (0..object.image.count).any(|index| {
                    object.image.segment(index).is_ok_and(|segment| {
                        segment.flags & 1 != 0 && segment.contains(relative, 1)
                    })
                })
            })
        })
    }
}
