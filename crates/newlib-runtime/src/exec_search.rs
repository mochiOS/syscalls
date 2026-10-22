//! Own file/PATH text before candidate execution can enter policy callbacks.
use super::*;

struct SearchPath {
    pointer: *mut u8,
    length: usize,
    capacity: usize,
}

impl SearchPath {
    fn new() -> Self {
        Self {
            pointer: ptr::null_mut(),
            length: 0,
            capacity: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), c_int> {
        let required = self
            .length
            .checked_add(bytes.len())
            .filter(|length| *length <= isize::MAX as usize)
            .ok_or(ENOMEM)?;
        if required > self.capacity {
            let capacity = required
                .checked_next_power_of_two()
                .filter(|capacity| *capacity <= isize::MAX as usize)
                .unwrap_or(required);
            // newlib owns allocation: this freestanding runtime must not
            // introduce a Rust allocator that recurses through libc malloc.
            let pointer = unsafe { malloc(capacity) }.cast::<u8>();
            if pointer.is_null() {
                return Err(ENOMEM);
            }
            if self.length != 0 {
                unsafe { ptr::copy_nonoverlapping(self.pointer, pointer, self.length) };
            }
            let old = self.pointer;
            self.pointer = pointer;
            self.capacity = capacity;
            if !old.is_null() {
                unsafe { free(old.cast()) };
            }
        }
        if !bytes.is_empty() {
            // Source is an owned capture chunk; initialized bytes alone are
            // exposed below, never the allocation's uninitialized capacity.
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), self.pointer.add(self.length), bytes.len())
            };
        }
        self.length = required;
        Ok(())
    }

    fn bytes(&self) -> &[u8] {
        if self.length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.pointer, self.length) }
        }
    }
}

impl Drop for SearchPath {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe { free(self.pointer.cast()) };
        }
    }
}

fn capture_path(source: *const c_char, output: &mut SearchPath) -> Result<(), c_int> {
    let mut chunk = [0; 256];
    loop {
        let address = (source as usize).checked_add(output.length).ok_or(EFAULT)?;
        match user_copy::capture_text(address as *const c_char, &mut chunk, ENAMETOOLONG) {
            Ok(length) => return output.append(&chunk[..length]),
            Err(ENAMETOOLONG) => output.append(&chunk)?,
            Err(error) => return Err(error),
        }
    }
}

fn search<T: Copy>(
    file: *const c_char,
    mut execute: impl FnMut(*const c_char) -> Result<T, c_int>,
) -> Result<T, c_int> {
    io_resources::with_initialized(
        || {
            Ok((
                [0u8; posix_protocol::MAX_PATH_LEN + 1],
                0usize,
                SearchPath::new(),
            ))
        },
        |(name, length, path)| {
            *length = user_copy::capture_text(
                file,
                &mut name[..posix_protocol::MAX_PATH_LEN],
                ENAMETOOLONG,
            )?;
            if *length == 0 {
                return Err(ENOENT);
            }
            if name[..*length].contains(&b'/') {
                return Ok(());
            }
            let pointer = unsafe { getenv(c"PATH".as_ptr()) };
            if pointer.is_null() {
                path.append(mochios_posix_client::configuration::DEFAULT_EXECUTABLE_PATH)
            } else {
                // PATH is a list, not a single pathname. Grow fallibly rather
                // than imposing PATH_MAX on the entire search list.
                capture_path(pointer, path)
            }
        },
        |(name, length, path)| {
            if name[..*length].contains(&b'/') {
                return execute(name.as_ptr().cast());
            }
            let mut candidate = [0u8; posix_protocol::MAX_PATH_LEN + 1];
            mochios_posix_client::spawn::search_path(
                path.bytes(),
                &name[..*length],
                &mut candidate,
                |candidate| execute(candidate.as_ptr().cast()),
            )
            .map_err(|error| match error {
                mochios_posix_client::spawn::PathSearchFailure::Candidate(error) => match error {
                    mochios_posix_client::spawn::PathCandidateError::EmptyFile => ENOENT,
                    mochios_posix_client::spawn::PathCandidateError::ContainsNul => EINVAL,
                    mochios_posix_client::spawn::PathCandidateError::TooLong => ENAMETOOLONG,
                },
                mochios_posix_client::spawn::PathSearchFailure::Errno(errno) => errno,
            })
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn execvp(file: *const c_char, argv: *const *mut c_char) -> c_int {
    let envp = unsafe { environ as *const *const c_char };
    result_with_errno(
        search(file, |candidate| {
            match execve_with_launch_context(candidate, argv.cast(), envp) {
                // Complete this PATH candidate even if the interpreter fails
                // with ENOENT/EACCES. Those are not errors from searching for
                // the original executable, so never try a later candidate.
                Err(ENOEXEC) => {
                    Ok(exec_interpreter::replace(candidate, argv.cast(), envp).map(|()| 0))
                }
                result => result.map(|()| Ok(0)),
            }
        })
        .and_then(|result| result),
        -1,
    )
}

#[unsafe(no_mangle)]
pub(super) extern "C" fn _posix_spawnp(
    pid: *mut c_int,
    file: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    match search(file, |candidate| {
        match _posix_spawn(pid, candidate, file_actions, attrp, argv, envp) {
            0 => Ok(()),
            errno => Err(errno),
        }
    }) {
        Ok(()) => 0,
        Err(errno) => errno,
    }
}
