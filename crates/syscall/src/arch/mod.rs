//! Instruction/register convention only; native syscall meanings stay shared.
#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod selected;
#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod selected;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("native syscall entry is not implemented for this architecture");
pub use selected::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
