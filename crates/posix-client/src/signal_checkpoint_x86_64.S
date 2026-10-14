// Identical client code can be linked through both Rust and the C runtime.
.section .text.mochios_posix_signal_checkpoint,"axG",@progbits,mochios_posix_signal_checkpoint,comdat
.globl mochios_posix_signal_checkpoint
.type mochios_posix_signal_checkpoint,@function
mochios_posix_signal_checkpoint:
    // Capture flags before allocation changes them. The 656-byte context is
    // 16-byte aligned; saved flags and the original return address follow it.
    pushfq
    sub rsp, 656
    mov [rsp + 0], r8
    mov [rsp + 8], r9
    mov [rsp + 16], r10
    mov [rsp + 24], r11
    mov [rsp + 32], r12
    mov [rsp + 40], r13
    mov [rsp + 48], r14
    mov [rsp + 56], r15
    mov [rsp + 64], rdi
    mov [rsp + 72], rsi
    mov [rsp + 80], rbp
    mov [rsp + 88], rbx
    mov [rsp + 96], rdx
    mov qword ptr [rsp + 104], 0
    mov [rsp + 112], rcx
    lea rax, [rsp + 672]
    mov [rsp + 120], rax
    mov rax, [rsp + 664]
    mov [rsp + 128], rax
    mov rax, [rsp + 656]
    mov [rsp + 136], rax
    // FXSAVE does not initialize every reserved byte. Never expose old stack
    // data through the context; the callback must also enter with DF clear.
    cld
    lea rdi, [rsp + 144]
    xor eax, eax
    mov ecx, 64
    rep stosq
    fxsave64 [rsp + 144]
    mov rax, [rsp + 64]
    mov rsi, [rsp + 72]
    mov rdi, rsp
    call rax

    // No Rust frame or cleanup is skipped: apply edits only after callback
    // completion, using a private base until R11 is restored last.
    mov r11, rsp
    fxrstor64 [r11 + 144]
    mov rsp, [r11 + 120]
    push qword ptr [r11 + 128]
    push qword ptr [r11 + 136]
    popfq
    mov r8, [r11 + 0]
    mov r9, [r11 + 8]
    mov r10, [r11 + 16]
    mov r12, [r11 + 32]
    mov r13, [r11 + 40]
    mov r14, [r11 + 48]
    mov r15, [r11 + 56]
    mov rdi, [r11 + 64]
    mov rsi, [r11 + 72]
    mov rbp, [r11 + 80]
    mov rbx, [r11 + 88]
    mov rdx, [r11 + 96]
    mov rax, [r11 + 104]
    mov rcx, [r11 + 112]
    mov r11, [r11 + 24]
    ret
.size mochios_posix_signal_checkpoint, .-mochios_posix_signal_checkpoint
.section .note.GNU-stack,"",@progbits
