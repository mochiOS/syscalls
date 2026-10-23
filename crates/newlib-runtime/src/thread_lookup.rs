//! Read the runtime's current TLS selector without entering the kernel.

use core::sync::atomic::{AtomicU64, Ordering};

/// Process-private hints, never authentication. Each hit must validate the
/// generation-bearing token and its TLS base against the live thread record.
/// Keep revision and token in one atomic word so colliding writers cannot
/// publish a token from one lifecycle revision with another's revision.
pub(super) struct TokenCache([AtomicU64; 64]);

impl TokenCache {
    pub(super) const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 64])
    }

    fn bucket(&self, base: u64) -> &AtomicU64 {
        &self.0[((base >> 4) ^ (base >> 16)) as usize & 63]
    }

    pub(super) fn get(&self, base: u64, revision: u32) -> Option<u32> {
        let value = self.bucket(base).load(Ordering::Relaxed);
        (revision != 0 && revision != u32::MAX && value >> 32 == u64::from(revision))
            .then_some(value as u32)
    }

    pub(super) fn insert(&self, base: u64, revision: u32, token: u32) {
        self.bucket(base).store(
            (u64::from(revision) << 32) | u64::from(token),
            Ordering::Relaxed,
        );
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "mochios"))]
fn cpu_supports_local_base() -> bool {
    core::arch::x86_64::__cpuid(0).eax >= 7 && core::arch::x86_64::__cpuid_count(7, 0).ebx & 1 != 0
}

#[cfg(all(target_arch = "x86_64", target_os = "mochios"))]
pub(super) fn local_base() -> Option<u64> {
    use core::sync::atomic::{AtomicU8, Ordering};
    // mnu enables CR4.FSGSBASE on supported CPUs. Unsupported machines keep
    // using ExecutionIdentityRead; never execute an optional instruction there.
    static SUPPORT: AtomicU8 = AtomicU8::new(0);
    let supported = match SUPPORT.load(Ordering::Relaxed) {
        0 => {
            let supported = cpu_supports_local_base();
            SUPPORT.store(if supported { 1 } else { 2 }, Ordering::Relaxed);
            supported
        }
        1 => true,
        _ => false,
    };
    if !supported {
        return None;
    }
    let base: u64;
    // Safety: CPU support was checked and mochiOS enables the instruction.
    // Reading the selector does not dereference potentially absent TLS memory.
    unsafe {
        core::arch::asm!("rdfsbase {}", out(reg) base, options(nostack, nomem, preserves_flags));
    }
    (base != 0).then_some(base)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "mochios")))]
pub(super) fn local_base() -> Option<u64> {
    None
}
