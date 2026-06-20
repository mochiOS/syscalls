.section .text._start,"ax",@progbits
.global _start
.type _start,@function
_start:
    xorq %rbp, %rbp
    movq %rsp, %rdi
    andq $-16, %rsp
    subq $8, %rsp
    call _start_c
.Lhang:
    hlt
    jmp .Lhang

.section .note.GNU-stack,"",@progbits
