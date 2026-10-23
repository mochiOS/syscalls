//! Opt-in, allocation-free diagnostics. No application paths or payload bytes
//! are logged, and ordinary builds contain none of this instrumentation.
use super::*;
use core::fmt::{self, Write};

static READS: AtomicU64 = AtomicU64::new(0);
static OPENS: AtomicU64 = AtomicU64::new(0);
static GROWTH: AtomicU64 = AtomicU64::new(0);
static IDENTITIES: AtomicU64 = AtomicU64::new(0);

struct Buffer {
    bytes: [u8; 256],
    length: usize,
}
impl Write for Buffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.length.checked_add(text.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.length..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.length = end;
        Ok(())
    }
}
fn emit(arguments: fmt::Arguments<'_>) {
    let mut buffer = Buffer {
        bytes: [0; 256],
        length: 0,
    };
    let _ = buffer.write_fmt(arguments);
    let _ = syscall::raw_syscall2(
        syscall::SyscallNumber::DebugWrite,
        buffer.bytes.as_ptr() as u64,
        buffer.length as u64,
    );
}

pub(super) struct Trace {
    kind: &'static str,
    id: u64,
    started: u64,
}
impl Trace {
    fn begin(kind: &'static str, counter: &AtomicU64, first: i64, second: u64) -> Self {
        let id = counter.fetch_add(1, Ordering::Relaxed);
        let started = monotonic_nanoseconds().unwrap_or(0);
        emit(format_args!(
            "runtime: {kind} begin id={id} first={first} second={second}\n"
        ));
        Self { kind, id, started }
    }
    pub(super) fn finish(self, result: impl fmt::Debug) {
        let elapsed = monotonic_nanoseconds()
            .unwrap_or(self.started)
            .saturating_sub(self.started);
        emit(format_args!(
            "runtime: {} end id={} elapsed_ns={} result={:?}\n",
            self.kind, self.id, elapsed, result
        ));
    }
}
pub(super) fn read(fd: c_int, length: usize) -> Option<Trace> {
    if length < 4096 {
        return None;
    }
    // Exponential sampling bounds output during a long sequence of short reads.
    let next = READS.load(Ordering::Relaxed);
    let trace = next == 0 || next.is_power_of_two();
    if trace {
        Some(Trace::begin("read", &READS, i64::from(fd), length as u64))
    } else {
        READS.fetch_add(1, Ordering::Relaxed);
        None
    }
}
pub(super) fn open(flags: c_int) -> Trace {
    Trace::begin("open", &OPENS, i64::from(flags), 0)
}
pub(super) fn growth(increment: isize) -> Option<Trace> {
    (increment >= 1 << 20).then(|| Trace::begin("heap", &GROWTH, increment as i64, 0))
}

pub(super) fn identity(tls_available: bool) {
    let count = IDENTITIES.fetch_add(1, Ordering::Relaxed) + 1;
    if count >= 65536 && count.is_power_of_two() {
        emit(format_args!(
            "runtime: native identity calls={} tls_available={}\n",
            count, tls_available
        ));
    }
}
