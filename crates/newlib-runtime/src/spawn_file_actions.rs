//! Own the complete action list before creating a child or executing the list.
use super::*;

pub(super) struct Path(*mut c_char);
impl Path {
    pub(super) fn capture(source: usize) -> Result<Self, c_int> {
        let mut bytes = [0; posix_protocol::MAX_PATH_LEN + 1];
        let length = user_copy::capture_text(
            source as *const c_char,
            &mut bytes[..posix_protocol::MAX_PATH_LEN],
            ENAMETOOLONG,
        )?;
        let pointer = unsafe { malloc(length + 1) }.cast::<c_char>();
        if pointer.is_null() {
            return Err(ENOMEM);
        }
        // Includes the zero-initialized trailing NUL; source is owned text.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.cast(), length + 1) };
        Ok(Self(pointer))
    }
    pub(super) fn as_ptr(&self) -> *const c_char {
        self.0
    }
    // Transfer the allocation only when the C action builder takes ownership.
    pub(super) fn into_raw(self) -> *mut c_char {
        core::mem::ManuallyDrop::new(self).0
    }
}
impl Drop for Path {
    fn drop(&mut self) {
        unsafe { free(self.0.cast()) };
    }
}

pub(super) enum Action {
    Close(c_int),
    Dup2 {
        source: c_int,
        target: c_int,
    },
    Open {
        fd: c_int,
        flags: c_int,
        mode: u32,
        path: Path,
    },
    Chdir(Path),
    Fchdir(c_int),
}
struct Node {
    next: *mut Node,
    action: Action,
}
pub(super) struct Actions {
    head: *mut Node,
    tail: *mut Node,
}
impl Actions {
    fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }

    fn append(&mut self) -> Result<*mut Node, c_int> {
        let node = unsafe { malloc(core::mem::size_of::<Node>()) }.cast::<Node>();
        if node.is_null() {
            return Err(ENOMEM);
        }
        unsafe {
            node.write(Node {
                next: ptr::null_mut(),
                action: Action::Close(-1),
            });
        }
        if self.tail.is_null() {
            self.head = node;
        } else {
            unsafe {
                (*self.tail).next = node;
            }
        }
        self.tail = node;
        Ok(node)
    }

    fn capture(&mut self, source: *const c_void) -> Result<(), c_int> {
        if source.is_null() {
            return Ok(());
        }
        let mut pointer = [0; core::mem::size_of::<usize>()];
        user_copy::read(source.cast(), &mut pointer)?;
        let object = usize::from_ne_bytes(pointer);
        if object == 0 {
            return Ok(());
        }
        let head = object
            .checked_add(core::mem::offset_of!(PosixSpawnFileActions, fa_list))
            .and_then(|offset| {
                offset.checked_add(core::mem::offset_of!(
                    StailqHead<PosixSpawnFileActionsEntry>,
                    stqh_first
                ))
            })
            .ok_or(EFAULT)?;
        user_copy::read(head as *const u8, &mut pointer)?;
        let mut current = usize::from_ne_bytes(pointer);
        // Brent's cycle check uses captured links only: linear traversal,
        // constant detector storage, no extra reads from mutable caller data.
        let mut anchor = current;
        let mut window = 1usize;
        let mut steps = 0usize;
        while current != 0 {
            if steps == window {
                anchor = current;
                window = window.saturating_mul(2);
                steps = 0;
            }
            let node = self.append()?;
            let mut bytes = [0; core::mem::size_of::<PosixSpawnFileActionsEntry>()];
            user_copy::read(current as *const u8, &mut bytes)?;
            let data = core::mem::offset_of!(PosixSpawnFileActionsEntry, fae_data);
            let kind = integer::<4>(
                &bytes,
                core::mem::offset_of!(PosixSpawnFileActionsEntry, fae_action),
            );
            let fd = c_int::from_ne_bytes(integer::<4>(
                &bytes,
                core::mem::offset_of!(PosixSpawnFileActionsEntry, fae_fildes),
            ));
            let action = match c_int::from_ne_bytes(kind) {
                FAE_CLOSE => Action::Close(fd),
                FAE_DUP2 => Action::Dup2 {
                    source: fd,
                    target: c_int::from_ne_bytes(integer::<4>(&bytes, data)),
                },
                FAE_OPEN => Action::Open {
                    fd,
                    flags: c_int::from_ne_bytes(integer::<4>(
                        &bytes,
                        data + core::mem::offset_of!(PosixSpawnFileActionOpen, oflag),
                    )),
                    mode: u32::from_ne_bytes(integer::<4>(
                        &bytes,
                        data + core::mem::offset_of!(PosixSpawnFileActionOpen, mode),
                    )),
                    path: Path::capture(usize::from_ne_bytes(integer(&bytes, data)))?,
                },
                FAE_CHDIR => {
                    Action::Chdir(Path::capture(usize::from_ne_bytes(integer(&bytes, data)))?)
                }
                FAE_FCHDIR => Action::Fchdir(c_int::from_ne_bytes(integer::<4>(&bytes, data))),
                _ => return Err(EINVAL),
            };
            unsafe {
                (*node).action = action;
            }
            current = usize::from_ne_bytes(integer(
                &bytes,
                core::mem::offset_of!(PosixSpawnFileActionsEntry, fae_list)
                    + core::mem::offset_of!(StailqEntry<PosixSpawnFileActionsEntry>, stqe_next),
            ));
            steps += 1;
            if current != 0 && current == anchor {
                return Err(EINVAL);
            }
        }
        Ok(())
    }

    pub(super) fn apply(
        &self,
        mut apply: impl FnMut(&Action) -> Result<(), c_int>,
    ) -> Result<(), c_int> {
        let mut current = self.head;
        while !current.is_null() {
            let node = unsafe { &*current };
            apply(&node.action)?;
            current = node.next;
        }
        Ok(())
    }
}
impl Drop for Actions {
    fn drop(&mut self) {
        let mut current = self.head;
        while !current.is_null() {
            let next = unsafe { (*current).next };
            unsafe {
                ptr::drop_in_place(current);
                free(current.cast());
            }
            current = next;
        }
    }
}
fn integer<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("C action field fits its structure")
}

pub(super) fn with(source: *const c_void, apply: impl FnOnce(&Actions) -> c_int) -> c_int {
    match io_resources::with_initialized(
        || Ok(Actions::new()),
        |actions| actions.capture(source),
        |actions| Ok(apply(actions)),
    ) {
        Ok(status) => status,
        Err(error) => error,
    }
}
