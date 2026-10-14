.text
.global sigsetjmp
.type sigsetjmp,@function
sigsetjmp:
    mov [rdi], rbx
    mov [rdi + 8], rbp
    mov [rdi + 16], r12
    mov [rdi + 24], r13
    mov [rdi + 32], r14
    mov [rdi + 40], r15
    lea rax, [rsp + 8]
    mov [rdi + 48], rax
    mov rax, [rsp]
    mov [rdi + 56], rax
    sub rsp, 8
    call __mochios_sigsetjmp_prepare
    add rsp, 8
    xor eax, eax
    ret
.size sigsetjmp, .-sigsetjmp

/* Everything is read before restoring the destination stack and reopening
   delivery. No abandoned stack or workspace is touched after that point. */
.global __mochios_sigjump_restore
.type __mochios_sigjump_restore,@function
__mochios_sigjump_restore:
    mov eax, esi
    test eax, eax
    jne 1f
    mov eax, 1
1:
    mov r8, [rdi + 56]
    mov r9, [rdi + 48]
    mov r10, rdx
    mov r11d, ecx
    mov rbx, [rdi]
    mov rbp, [rdi + 8]
    mov r12, [rdi + 16]
    mov r13, [rdi + 24]
    mov r14, [rdi + 32]
    mov r15, [rdi + 40]
    mov rsp, r9
    mov [r10], r11d
    jmp r8
.size __mochios_sigjump_restore, .-__mochios_sigjump_restore
.section .note.GNU-stack,"",@progbits
