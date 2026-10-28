//! Initial static TLS descriptor ABI. The caller supplies the descriptor in
//! RAX and may keep every other GPR/vector register live across the call.
core::arch::global_asm!(
    ".section .text.__mochios_tlsdesc_static,\"ax\",@progbits",
    ".p2align 4",
    ".global __mochios_tlsdesc_static",
    ".type __mochios_tlsdesc_static,@function",
    "__mochios_tlsdesc_static:",
    "mov rax, [rax + 8]",
    "ret",
    ".size __mochios_tlsdesc_static, .-__mochios_tlsdesc_static",
    ".section .text.__mochios_tlsdesc_weak,\"ax\",@progbits",
    ".p2align 4",
    ".global __mochios_tlsdesc_weak",
    ".type __mochios_tlsdesc_weak,@function",
    "__mochios_tlsdesc_weak:",
    "mov rax, [rax + 8]",
    "sub rax, fs:[0]",
    "ret",
    ".size __mochios_tlsdesc_weak, .-__mochios_tlsdesc_weak",
);
unsafe extern "C" {
    pub(super) fn __mochios_tlsdesc_static();
    pub(super) fn __mochios_tlsdesc_weak();
}
pub(super) fn retain() {
    core::hint::black_box(__mochios_tlsdesc_static as unsafe extern "C" fn());
    core::hint::black_box(__mochios_tlsdesc_weak as unsafe extern "C" fn());
}
