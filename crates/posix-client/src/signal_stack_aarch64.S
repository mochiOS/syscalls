.section .text.mochios_posix_call_on_stack,"axG",%progbits,mochios_posix_call_on_stack,comdat
.global mochios_posix_call_on_stack
.type mochios_posix_call_on_stack,%function
mochios_posix_call_on_stack:
    stp x19, x30, [sp, #-16]!
    mov x19, sp
    and x0, x0, #-16
    mov sp, x0
    mov x0, x2
    blr x1
    mov sp, x19
    ldp x19, x30, [sp], #16
    ret
.size mochios_posix_call_on_stack, .-mochios_posix_call_on_stack

.section .text.mochios_posix_enter_on_stack,"axG",%progbits,mochios_posix_enter_on_stack,comdat
.global mochios_posix_enter_on_stack
.type mochios_posix_enter_on_stack,%function
mochios_posix_enter_on_stack:
    and x3, x0, #-16
    mov sp, x3
    mov x0, x2
    mov x29, #0
    mov x30, #0
    br x1
.size mochios_posix_enter_on_stack, .-mochios_posix_enter_on_stack
.section .note.GNU-stack,"",%progbits
