//! Owned exec text; application pointers never survive into policy or loader IPC.
use super::*;
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    length: usize,
}

pub(super) struct Inputs {
    path: [u8; posix_protocol::MAX_PATH_LEN],
    path_length: usize,
    text: [u8; mnu_abi::process_image::MAX_STACK_BYTES],
    used: usize,
    spans: [[Span; MAX_EXEC_VECTOR_ENTRIES]; 2],
    counts: [usize; 2],
}
impl Inputs {
    pub(super) fn new() -> Self {
        Self {
            path: [0; posix_protocol::MAX_PATH_LEN],
            path_length: 0,
            text: [0; mnu_abi::process_image::MAX_STACK_BYTES],
            used: 0,
            spans: [[Span {
                start: 0,
                length: 0,
            }; MAX_EXEC_VECTOR_ENTRIES]; 2],
            counts: [0; 2],
        }
    }

    pub(super) fn capture(
        &mut self,
        path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> Result<(), c_int> {
        self.used = 0;
        self.counts = [0; 2];
        self.path_length = user_copy::capture_text(
            path,
            &mut self.path[..posix_protocol::MAX_PATH_LEN - 1],
            ENAMETOOLONG,
        )?;
        if self.path_length == 0 {
            return Err(ENOENT);
        }
        self.capture_vector(0, argv)?;
        self.capture_vector(1, envp)
    }

    /// Descriptor execution has no pathname input. Snapshot vectors with the
    /// same fault-safe copy and shared text budget used by pathname exec.
    pub(super) fn capture_fd(
        &mut self,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> Result<(), c_int> {
        self.used = 0;
        self.counts = [0; 2];
        self.path_length = 0;
        self.capture_vector(0, argv)?;
        self.capture_vector(1, envp)
    }

    fn capture_vector(&mut self, kind: usize, vector: *const *const c_char) -> Result<(), c_int> {
        if vector.is_null() {
            return Ok(());
        }
        for index in 0..MAX_EXEC_VECTOR_ENTRIES {
            let address = (vector as usize)
                .checked_add(index * core::mem::size_of::<usize>())
                .ok_or(EFAULT)?;
            let mut bytes = [0; core::mem::size_of::<usize>()];
            user_copy::read(address as *const u8, &mut bytes)?;
            let pointer = usize::from_ne_bytes(bytes);
            if pointer == 0 {
                self.counts[kind] = index;
                return Ok(());
            }
            if self.used == self.text.len() {
                return Err(E2BIG);
            }
            let length = user_copy::capture_text(
                pointer as *const c_char,
                &mut self.text[self.used..],
                E2BIG,
            )?;
            let next = self
                .used
                .checked_add(length)
                .and_then(|end| end.checked_add(1))
                .filter(|&end| end <= self.text.len())
                .ok_or(E2BIG)?;
            self.spans[kind][index] = Span {
                start: self.used,
                length,
            };
            self.text[next - 1] = 0;
            self.used = next;
        }
        Err(E2BIG)
    }

    pub(super) fn path(&self) -> &[u8] {
        &self.path[..self.path_length]
    }

    /// Borrow C vectors from owned, explicitly terminated text. Callers must
    /// retain this snapshot throughout the synchronous exec preparation.
    pub(super) fn c_vectors(
        &self,
        argv: &mut [*const c_char; MAX_EXEC_VECTOR_ENTRIES],
        envp: &mut [*const c_char; MAX_EXEC_VECTOR_ENTRIES],
    ) -> (usize, usize) {
        for (kind, output) in [argv, envp].into_iter().enumerate() {
            output.fill(core::ptr::null());
            for (destination, span) in output
                .iter_mut()
                .zip(&self.spans[kind][..self.counts[kind]])
            {
                *destination = self.text[span.start..].as_ptr().cast();
            }
        }
        (self.counts[0], self.counts[1])
    }

    pub(super) fn vectors<'a>(
        &'a self,
        argv: &mut [&'a [u8]; MAX_EXEC_VECTOR_ENTRIES],
        envp: &mut [&'a [u8]; MAX_EXEC_VECTOR_ENTRIES],
    ) -> (usize, usize) {
        for (kind, output) in [argv, envp].into_iter().enumerate() {
            for (destination, span) in output
                .iter_mut()
                .zip(&self.spans[kind][..self.counts[kind]])
            {
                *destination = &self.text[span.start..span.start + span.length];
            }
        }
        (self.counts[0], self.counts[1])
    }
}
