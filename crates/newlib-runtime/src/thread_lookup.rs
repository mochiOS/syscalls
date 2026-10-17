//! Read the runtime's current TLS selector without entering the kernel.

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
