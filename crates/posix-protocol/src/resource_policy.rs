//! Versioned resource policy for one process, stored in shared RAM.
//!
//! The service owns the writable mapping; clients must receive only READ|MAP
//! authority and map it read-only. No identity, pointer or native Handle is
//! embedded here. Binding a page to a process is an authenticated IPC policy.
//! Fork needs a new child's page; sharing the parent's policy is incorrect.
//!
//! All words have little-endian representation and require aligned atomic
//! u64 access. Header words are immutable after publication. The generation
//! brackets updates so readers never combine parts of different limits.
use crate::{RLIMIT_COUNT, ResourceLimit};
use core::sync::atomic::{AtomicU64, Ordering, fence};

pub const MAGIC: u64 = u64::from_le_bytes(*b"POSXRLM\0");
pub const VERSION: u32 = 1;
pub const HEADER_LEN: usize = 24;
pub const LIMIT_LEN: usize = 16;
pub const BASE_BYTE_LEN: usize = HEADER_LEN + RLIMIT_COUNT as usize * LIMIT_LEN;
/// The v1 limit prefix remains unchanged for existing SDK readers. The lock
/// state extension is independently tagged, and never interpreted by mnu.
pub const BYTE_LEN: usize = BASE_BYTE_LEN + 16;
const LOCK_STATE_MAGIC: u64 = u64::from_le_bytes(*b"LCKSTAT1");
pub const READER_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP;
const FORMAT: u64 = (VERSION as u64) << 32 | RLIMIT_COUNT as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLayout,
    InvalidResource,
    InvalidLimit,
    Busy,
    Exhausted,
    UnsupportedTarget,
}

#[repr(C, align(8))]
pub struct ResourcePolicy {
    magic: AtomicU64,
    format: AtomicU64,
    generation: AtomicU64,
    limits: [[AtomicU64; 2]; RLIMIT_COUNT as usize],
    lock_format: AtomicU64,
    record_locks: AtomicU64,
}

const _: () = {
    assert!(core::mem::size_of::<ResourcePolicy>() == BYTE_LEN);
    assert!(core::mem::align_of::<ResourcePolicy>() == 8);
    assert!(core::mem::offset_of!(ResourcePolicy, generation) == 16);
    assert!(core::mem::offset_of!(ResourcePolicy, limits) == HEADER_LEN);
    assert!(core::mem::offset_of!(ResourcePolicy, lock_format) == BASE_BYTE_LEN);
};

impl ResourcePolicy {
    /// Initialize privately, before delegating any readable mapping. The
    /// backing must remain mapped for every borrow of this atomic view.
    pub fn new(limits: [ResourceLimit; RLIMIT_COUNT as usize]) -> Result<Self, Error> {
        if limits.iter().any(|limit| limit.soft > limit.hard) {
            return Err(Error::InvalidLimit);
        }
        Ok(Self {
            magic: AtomicU64::new(MAGIC.to_le()),
            format: AtomicU64::new(FORMAT.to_le()),
            generation: AtomicU64::new(0),
            limits: core::array::from_fn(|index| {
                [
                    AtomicU64::new(limits[index].soft.to_le()),
                    AtomicU64::new(limits[index].hard.to_le()),
                ]
            }),
            lock_format: AtomicU64::new(LOCK_STATE_MAGIC.to_le()),
            record_locks: AtomicU64::new(0),
        })
    }

    /// Only a service-owned writable mapping may publish. One atomic scalar
    /// is independent of the limit seqlock; no fallible work or allocation.
    pub fn publish_record_locks(&self, held: bool) {
        self.record_locks
            .store(u64::from(held).to_le(), Ordering::SeqCst);
    }

    /// Read-only-safe access to authoritative process state, with no RPC.
    pub fn read_record_locks(&self) -> Result<bool, Error> {
        self.validate()?;
        if u64::from_le(self.lock_format.load(Ordering::Relaxed)) != LOCK_STATE_MAGIC {
            return Err(Error::InvalidLayout);
        }
        let value = u64::from_le(self.record_locks.load(Ordering::Relaxed));
        fence(Ordering::Acquire);
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidLayout),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        // Rust guarantees read-only eight-byte Relaxed loads on these
        // 64-bit targets, not arbitrary AtomicU64 targets/orderings.
        // https://doc.rust-lang.org/std/sync/atomic/index.html#atomic-accesses-to-read-only-memory
        if !cfg!(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "loongarch64",
            target_arch = "mips64",
            target_arch = "powerpc64",
            target_arch = "riscv64",
            target_arch = "sparc64",
            target_arch = "s390x",
        )) {
            return Err(Error::UnsupportedTarget);
        }
        if u64::from_le(self.magic.load(Ordering::Relaxed)) != MAGIC
            || u64::from_le(self.format.load(Ordering::Relaxed)) != FORMAT
        {
            return Err(Error::InvalidLayout);
        }
        Ok(())
    }

    /// One bounded attempt, with no RPC, allocation, lock or system call.
    /// Busy means a concurrent publisher won: yield/retry outside any locks,
    /// never substitute stale or unlimited policy. Only Relaxed loads touch
    /// the read-only page. The first acquire fence synchronizes with the
    /// observed even publication; the second synchronizes with any observed
    /// newer data store, forcing the final generation check to notice its
    /// preceding odd marker. Writer data stores must remain release-capable.
    pub fn read(&self, resource: u32) -> Result<ResourceLimit, Error> {
        self.validate()?;
        let words = self
            .limits
            .get(resource as usize)
            .ok_or(Error::InvalidResource)?;
        let before = u64::from_le(self.generation.load(Ordering::Relaxed));
        if before & 1 != 0 {
            return Err(Error::Busy);
        }
        fence(Ordering::Acquire);
        let value = ResourceLimit {
            soft: u64::from_le(words[0].load(Ordering::Relaxed)),
            hard: u64::from_le(words[1].load(Ordering::Relaxed)),
        };
        fence(Ordering::Acquire);
        if u64::from_le(self.generation.load(Ordering::Relaxed)) != before {
            return Err(Error::Busy);
        }
        if value.soft > value.hard {
            return Err(Error::InvalidLimit);
        }
        Ok(value)
    }

    /// Publish an already-authorized service decision. The caller must own a
    /// writable mapping; exposing this method never grants memory authority.
    /// Validation, concurrent writers and generation exhaustion leave all
    /// values unchanged. Exhaustion never wraps into a possible ABA match.
    pub fn publish(&self, resource: u32, value: ResourceLimit) -> Result<(), Error> {
        self.validate()?;
        let words = self
            .limits
            .get(resource as usize)
            .ok_or(Error::InvalidResource)?;
        if value.soft > value.hard {
            return Err(Error::InvalidLimit);
        }
        let generation = u64::from_le(self.generation.load(Ordering::SeqCst));
        if generation & 1 != 0 {
            return Err(Error::Busy);
        }
        let next = generation.checked_add(2).ok_or(Error::Exhausted)?;
        self.generation
            .compare_exchange(
                generation.to_le(),
                (generation + 1).to_le(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| Error::Busy)?;
        // No allocation, fallible work or user callback while the generation
        // is odd. Even generation is the final publication/linearization.
        words[0].store(value.soft.to_le(), Ordering::SeqCst);
        words[1].store(value.hard.to_le(), Ordering::SeqCst);
        self.generation.store(next.to_le(), Ordering::SeqCst);
        Ok(())
    }
}
