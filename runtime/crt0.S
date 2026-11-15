#if defined(__aarch64__)
#define PROGBITS %progbits
#define FUNCTION %function
#define OBJECT %object
#elif defined(__x86_64__)
#define PROGBITS @progbits
#define FUNCTION @function
#define OBJECT @object
#else
#error "No native mochiOS process entry for this architecture"
#endif

.section .text._start,"ax",PROGBITS
.global _start
.type _start,FUNCTION
_start:
#if defined(__aarch64__)
    mov x29, xzr
    mov x30, xzr
    mov x0, sp
    bl _start_c
.Lhang:
    brk #0
    b .Lhang
#else
    xorq %rbp, %rbp
    movq %rsp, %rdi
    andq $-16, %rsp
    call _start_c
.Lhang:
    hlt
    jmp .Lhang
#endif

.section .data.__dso_handle,"aw",PROGBITS
.balign 8
.global __dso_handle
.hidden __dso_handle
.type __dso_handle,OBJECT
.size __dso_handle,8
__dso_handle:
    .quad __dso_handle

.section .note.GNU-stack,"",PROGBITS
