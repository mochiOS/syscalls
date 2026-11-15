.text
.global setjmp
.global _setjmp
.type setjmp,%function
.type _setjmp,%function
setjmp:
_setjmp:
    mov w1, #0
    b sigsetjmp
.size setjmp, .-setjmp
.size _setjmp, .-_setjmp

.global longjmp
.global _longjmp
.type longjmp,%function
.type _longjmp,%function
longjmp:
_longjmp:
    b siglongjmp
.size longjmp, .-longjmp
.size _longjmp, .-_longjmp

.global sigsetjmp
.type sigsetjmp,%function
sigsetjmp:
    stp x19, x20, [x0]
    stp x21, x22, [x0, #16]
    stp x23, x24, [x0, #32]
    stp x25, x26, [x0, #48]
    stp x27, x28, [x0, #64]
    stp x29, x30, [x0, #80]
    mov x2, sp
    str x2, [x0, #96]
    stp d8, d9, [x0, #104]
    stp d10, d11, [x0, #120]
    stp d12, d13, [x0, #136]
    stp d14, d15, [x0, #152]
    stp x0, x30, [sp, #-16]!
    bl __mochios_sigsetjmp_prepare
    ldp x0, x30, [sp], #16
    mov w0, #0
    ret
.size sigsetjmp, .-sigsetjmp

// Read every abandoned-stack byte before publishing the destination SP and
// reopening delivery. FPCR/FPSR remain the current longjmp caller's environment.
.global __mochios_sigjump_restore
.type __mochios_sigjump_restore,%function
__mochios_sigjump_restore:
    mov x4, x0
    cmp w1, #0
    csinc w0, w1, wzr, ne
    ldr x5, [x4, #96]
    ldp d8, d9, [x4, #104]
    ldp d10, d11, [x4, #120]
    ldp d12, d13, [x4, #136]
    ldp d14, d15, [x4, #152]
    ldp x19, x20, [x4]
    ldp x21, x22, [x4, #16]
    ldp x23, x24, [x4, #32]
    ldp x25, x26, [x4, #48]
    ldp x27, x28, [x4, #64]
    ldp x29, x30, [x4, #80]
    mov sp, x5
    stlr w3, [x2]
    ret
.size __mochios_sigjump_restore, .-__mochios_sigjump_restore
.section .note.GNU-stack,"",%progbits
