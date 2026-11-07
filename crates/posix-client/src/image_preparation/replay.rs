//! Bounded loader transcripts, replayed by policy before authorizing transformed code.
//! Paths select authenticated catalog entries; they never authenticate bytes.
use super::*;
use core::cell::{Cell, RefCell};
const HEADER: usize = 16;
const PREFIX: usize = 20;
const MAGIC: &[u8; 8] = b"MEXR0001";
const ROOT: u32 = 0;
const DEPENDENCY: u32 = 1;
const INTERPRETER: u32 = 2;
const ENTROPY: u32 = 3;
const MAX_EVENTS: usize = 8192 + 8;

#[derive(Clone, Copy)]
struct Event<'a> {
    tag: u32,
    path: &'a [u8],
    bytes: &'a [u8],
    end: usize,
}
fn event(bytes: &[u8], at: usize) -> Result<Event<'_>, c_int> {
    let head = bytes
        .get(at..at.checked_add(HEADER).ok_or(ENOEXEC)?)
        .ok_or(ENOEXEC)?;
    let tag = u32::from_le_bytes(head[..4].try_into().unwrap());
    let path_len = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
    let length =
        usize::try_from(u64::from_le_bytes(head[8..].try_into().unwrap())).map_err(|_| EFBIG)?;
    if path_len > 4096 || length == 0 || length > MAX_IMAGE {
        return Err(ENOEXEC);
    }
    let start = at.checked_add(HEADER).ok_or(ENOEXEC)?;
    let middle = start.checked_add(path_len).ok_or(ENOEXEC)?;
    let end = middle.checked_add(length).ok_or(ENOEXEC)?;
    let path = bytes.get(start..middle).ok_or(ENOEXEC)?;
    let payload = bytes.get(middle..end).ok_or(ENOEXEC)?;
    if path.contains(&0)
        || match tag {
            ROOT => !path.is_empty(),
            DEPENDENCY | INTERPRETER => path.is_empty(),
            ENTROPY => !path.is_empty() || !matches!(length, 8 | 16),
            _ => true,
        }
    {
        return Err(ENOEXEC);
    }
    Ok(Event {
        tag,
        path,
        bytes: payload,
        end,
    })
}
fn source_fields(source: Source<'_>) -> (u32, &[u8]) {
    match source {
        Source::Root => (ROOT, &[]),
        Source::Dependency { path, .. } => (DEPENDENCY, path),
        Source::Interpreter { path } => (INTERPRETER, path),
    }
}

fn prefix(bytes: &[u8]) -> Result<(usize, Environment<'_>), c_int> {
    if bytes.get(..8) != Some(MAGIC.as_slice()) || bytes.len() < PREFIX {
        return Err(ENOEXEC);
    }
    let mut start = PREFIX;
    let mut values = [None; 3];
    for (i, value) in values.iter_mut().enumerate() {
        let n = u32::from_le_bytes(bytes[8 + i * 4..12 + i * 4].try_into().unwrap()) as usize;
        if n > 65536 {
            return Err(E2BIG);
        }
        let end = start.checked_add(n).ok_or(ENOEXEC)?;
        let b = bytes.get(start..end).ok_or(ENOEXEC)?;
        if b.contains(&0) {
            return Err(ENOEXEC);
        }
        if n != 0 {
            *value = Some(b)
        }
        start = end;
    }
    let environment = Environment {
        library_path: values[0],
        preload: values[1],
        audit: values[2],
    };
    Ok((start, environment))
}
/// Return the bounded original executable for authenticated catalog selection.
pub fn original(bytes: &[u8]) -> Result<&[u8], c_int> {
    if bytes.len() > MAX_IMAGE {
        return Err(EFBIG);
    }
    let (start, _) = prefix(bytes)?;
    let e = event(bytes, start)?;
    if e.tag != ROOT {
        return Err(ENOEXEC);
    }
    Ok(e.bytes)
}

fn append<B: Backend>(buffer: &mut Buffer<B>, data: &[u8]) {
    assert!(buffer.length + data.len() <= buffer.capacity);
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), buffer.pointer.add(buffer.length), data.len());
    }
    buffer.length += data.len();
}

/// An operation-owned transcript. Its owner must survive abandoned callbacks,
/// just like Preparation. Mutations run inside the underlying critical section.
pub struct Recording<B: Backend> {
    inner: B,
    bytes: RefCell<Buffer<B>>,
    events: Cell<usize>,
}
impl<B: Backend> Recording<B> {
    /// Start recording one preparation, without taking ownership of its root file.
    pub fn new(inner: B, environment: Environment<'_>) -> Result<Self, c_int> {
        let values = [
            environment.library_path.unwrap_or(&[]),
            environment.preload.unwrap_or(&[]),
            environment.audit.unwrap_or(&[]),
        ];
        let length = values
            .iter()
            .try_fold(PREFIX, |n, b| n.checked_add(b.len()).ok_or(EFBIG))?;
        if values.iter().any(|b| b.len() > 65536 || b.contains(&0)) {
            return Err(E2BIG);
        }
        let mut bytes = Buffer::<B>::default();
        bytes.reserve(length)?;
        append(&mut bytes, MAGIC);
        for b in values {
            append(&mut bytes, &(b.len() as u32).to_le_bytes());
        }
        for b in values {
            append(&mut bytes, b);
        }
        Ok(Self {
            inner,
            bytes: RefCell::new(bytes),
            events: Cell::new(0),
        })
    }
    /// Borrow the completed immutable transcript while its operation owner lives.
    pub fn with_bytes<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        f(self.bytes.borrow().bytes())
    }
    fn append(&self, tag: u32, path: &[u8], data: &[u8]) -> Result<(), c_int> {
        B::critical(|| {
            let mut bytes = self.bytes.borrow_mut();
            let length = HEADER
                .checked_add(path.len())
                .and_then(|n| n.checked_add(data.len()))
                .ok_or(EFBIG)?;
            if self.events.get() == MAX_EVENTS
                || bytes
                    .length
                    .checked_add(length)
                    .is_none_or(|n| n > MAX_IMAGE)
            {
                return Err(EFBIG);
            }
            let end = bytes.length.checked_add(length).ok_or(EFBIG)?;
            bytes.reserve(end)?;
            append(&mut bytes, &tag.to_le_bytes());
            append(&mut bytes, &(path.len() as u32).to_le_bytes());
            append(&mut bytes, &(data.len() as u64).to_le_bytes());
            append(&mut bytes, path);
            append(&mut bytes, data);
            self.events.set(self.events.get() + 1);
            Ok(())
        })
    }
}
// Ownership and callback exclusion are delegated to B; the transcript is held
// in the same tracked operation owner as the loader, not in a temporary stack guard.
unsafe impl<B: Backend> Backend for Recording<B> {
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        B::critical(f)
    }
    fn allocate(n: usize) -> *mut u8 {
        B::allocate(n)
    }
    unsafe fn deallocate(p: *mut u8) {
        unsafe { B::deallocate(p) }
    }
    fn close(h: u32) {
        B::close(h)
    }
    fn read_at(&self, h: u32, b: &mut [u8], at: usize) -> Result<usize, c_int> {
        self.inner.read_at(h, b, at)
    }
    fn open_library(&self, p: &[u8]) -> Result<crate::ObjectHandleAttachment<u32>, c_int> {
        self.inner.open_library(p)
    }
    fn validate_library(&self, f: crate::ObjectHandleAttachment<u32>) -> Result<(), c_int> {
        self.inner.validate_library(f)
    }
    fn validate_captured(&self, s: Source<'_>, b: &[u8]) -> Result<(), c_int> {
        self.inner.validate_captured(s, b)?;
        let (t, p) = source_fields(s);
        self.append(t, p, b)
    }
    fn entropy(&self, b: &mut [u8]) -> Result<(), c_int> {
        self.inner.entropy(b)?;
        self.append(ENTROPY, &[], b)
    }
    fn create_image(&self, n: usize) -> Result<u32, c_int> {
        self.inner.create_image(n)
    }
    fn write_at(&self, h: u32, b: &[u8], at: usize) -> Result<usize, c_int> {
        self.inner.write_at(h, b, at)
    }
    fn readonly_image(&self, h: u32) -> Result<u32, c_int> {
        self.inner.readonly_image(h)
    }
    fn readonly_metadata(&self, h: u32) -> Result<u32, c_int> {
        self.inner.readonly_metadata(h)
    }
}

/// Reconstruct the common loader output from captured, catalog-authenticated
/// inputs. No caller Provider or filesystem is consulted. Supplied entropy
/// reproduces the caller's existing userspace ASLR choice; it grants no authority.
pub struct Replay<'a, B: Backend> {
    inner: &'a B,
    bytes: &'a [u8],
    cursor: Cell<usize>,
    start: usize,
    environment: Environment<'a>,
}
impl<'a, B: Backend> Replay<'a, B> {
    /// Validate the complete bounded transcript before allocating loader images.
    pub fn new(inner: &'a B, bytes: &'a [u8]) -> Result<Self, c_int> {
        if bytes.len() > MAX_IMAGE {
            return Err(EFBIG);
        }
        let (start, environment) = prefix(bytes)?;
        let mut at = start;
        let mut count = 0;
        while at < bytes.len() {
            let e = event(bytes, at)?;
            if (count == 0) != (e.tag == ROOT) || count == MAX_EVENTS {
                return Err(ENOEXEC);
            }
            at = e.end;
            count += 1;
        }
        if count == 0 {
            return Err(ENOEXEC);
        }
        Ok(Self {
            inner,
            bytes,
            cursor: Cell::new(start),
            start,
            environment,
        })
    }
    /// Exact original executable, before linking or relocation.
    pub fn root(&self) -> &'a [u8] {
        event(self.bytes, self.start)
            .expect("validated transcript")
            .bytes
    }
    /// Recorded loader controls, still filtered by authenticated caller credentials.
    pub fn environment(&self) -> Environment<'a> {
        self.environment
    }
    /// Reject omitted, extra or reordered loader operations.
    pub fn finish(&self) -> Result<(), c_int> {
        if self.cursor.get() == self.bytes.len() {
            Ok(())
        } else {
            Err(EACCES)
        }
    }
    fn next(&self) -> Result<Event<'a>, c_int> {
        event(self.bytes, self.cursor.get())
    }
}
unsafe impl<B: Backend> Backend for Replay<'_, B> {
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        B::critical(f)
    }
    fn allocate(n: usize) -> *mut u8 {
        B::allocate(n)
    }
    unsafe fn deallocate(p: *mut u8) {
        unsafe { B::deallocate(p) }
    }
    fn close(h: u32) {
        B::close(h)
    }
    fn read_at(&self, h: u32, b: &mut [u8], at: usize) -> Result<usize, c_int> {
        self.inner.read_at(h, b, at)
    }
    fn open_library(&self, path: &[u8]) -> Result<crate::ObjectHandleAttachment<u32>, c_int> {
        let e = self.next()?;
        if !matches!(e.tag, DEPENDENCY | INTERPRETER) || e.path != path {
            return Err(ENOENT);
        }
        let writer = B::critical(|| self.inner.create_image(e.bytes.len()))?;
        let result = (|| {
            let mut at = 0;
            while at < e.bytes.len() {
                let n = self.inner.write_at(writer, &e.bytes[at..], at)?;
                if n == 0 || n > e.bytes.len() - at {
                    return Err(EIO);
                }
                at += n;
            }
            B::critical(|| self.inner.readonly_image(writer))
        })();
        B::critical(|| B::close(writer));
        result.map(|handle| crate::ObjectHandleAttachment {
            handle,
            rights: posix_protocol::CHECK_EXECUTABLE_RIGHTS,
        })
    }
    fn validate_library(&self, _: crate::ObjectHandleAttachment<u32>) -> Result<(), c_int> {
        Ok(())
    }
    fn validate_captured(&self, s: Source<'_>, b: &[u8]) -> Result<(), c_int> {
        let e = self.next()?;
        let (t, p) = source_fields(s);
        if e.tag != t || e.path != p || e.bytes != b {
            return Err(EACCES);
        }
        self.inner.validate_captured(s, b)?;
        self.cursor.set(e.end);
        Ok(())
    }
    fn entropy(&self, b: &mut [u8]) -> Result<(), c_int> {
        let e = self.next()?;
        if e.tag != ENTROPY || e.bytes.len() != b.len() {
            return Err(EACCES);
        }
        b.copy_from_slice(e.bytes);
        self.cursor.set(e.end);
        Ok(())
    }
    fn create_image(&self, n: usize) -> Result<u32, c_int> {
        self.inner.create_image(n)
    }
    fn write_at(&self, h: u32, b: &[u8], at: usize) -> Result<usize, c_int> {
        self.inner.write_at(h, b, at)
    }
    fn readonly_image(&self, h: u32) -> Result<u32, c_int> {
        self.inner.readonly_image(h)
    }
    fn readonly_metadata(&self, h: u32) -> Result<u32, c_int> {
        self.inner.readonly_metadata(h)
    }
}
