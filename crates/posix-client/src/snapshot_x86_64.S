// The same client can occur in both a Rust dependency and the C runtime
// archive. Keep one identical continuation body when both are linked.
.section .text.mochios_posix_capture_snapshot,"axG",@progbits,mochios_posix_capture_snapshot,comdat
.globl mochios_posix_capture_snapshot
.type mochios_posix_capture_snapshot,@function
mochios_posix_capture_snapshot:
    // Save the complete native context before the backend can clone memory.
    // RDI = output context, RSI = opaque TLS base, RDX = capture backend.
    mov [rdi + 8], rsp
    mov [rdi + 16], rdi
    mov [rdi + 24], rsi
    mov qword ptr [rdi + 32], 0
    mov qword ptr [rdi + 40], 0
    mov qword ptr [rdi + 48], 0
    mov qword ptr [rdi + 56], 0
    mov qword ptr [rdi + 64], 0
    mov [rdi + 72], rbx
    mov [rdi + 80], rcx
    mov [rdi + 88], rdx
    mov [rdi + 96], rsi
    mov [rdi + 104], rbp
    mov [rdi + 112], r8
    mov [rdi + 120], r9
    mov [rdi + 128], r10
    mov [rdi + 136], r11
    mov [rdi + 144], r12
    mov [rdi + 152], r13
    mov [rdi + 160], r14
    mov [rdi + 168], r15
    lea rax, [rip + .Lmochios_posix_snapshot_child]
    mov [rdi], rax
    // The entry RSP points to the return address in the captured caller frame.
    // Align a separate backend frame; never replace that saved return address.
    sub rsp, 8
    call rdx
    add rsp, 8
    ret
.Lmochios_posix_snapshot_child:
    xor eax, eax
    ret
.size mochios_posix_capture_snapshot, .-mochios_posix_capture_snapshot
.section .note.GNU-stack,"",@progbits
