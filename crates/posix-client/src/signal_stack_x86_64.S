.section .text.mochios_posix_call_on_stack,"axG",@progbits,mochios_posix_call_on_stack,comdat
.globl mochios_posix_call_on_stack
.type mochios_posix_call_on_stack,@function
mochios_posix_call_on_stack:
    push r12
    mov r12, rsp
    mov rsp, rdi
    and rsp, -16
    mov rdi, rdx
    call rsi
    mov rsp, r12
    pop r12
    ret
.size mochios_posix_call_on_stack, .-mochios_posix_call_on_stack
.section .note.GNU-stack,"",@progbits
