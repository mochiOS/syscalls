.section .text._start,"ax",@progbits
.global _start
.type _start,@function
_start:
    xorq %rbp, %rbp
    movq %rsp, %rdi
    andq $-16, %rsp
    call _start_c
.Lhang:
    hlt
    jmp .Lhang

.section .data.__dso_handle,"aw",@progbits
.balign 8
.global __dso_handle
.hidden __dso_handle
.type __dso_handle,@object
.size __dso_handle,8
__dso_handle:
    .quad __dso_handle

.section .note.GNU-stack,"",@progbits
