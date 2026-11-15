// Synchronous AAPCS64 call boundary; no kernel signal policy is encoded.
.section .text.mochios_posix_signal_checkpoint,"axG",%progbits,mochios_posix_signal_checkpoint,comdat
.global mochios_posix_signal_checkpoint
.type mochios_posix_signal_checkpoint,%function
mochios_posix_signal_checkpoint:
    sub sp, sp, #800
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    add x16, sp, #800
    str x16, [sp, #248]
    str x30, [sp, #256]
    mrs x16, nzcv
    str x16, [sp, #264]
    stp q0, q1, [sp, #272]
    stp q2, q3, [sp, #304]
    stp q4, q5, [sp, #336]
    stp q6, q7, [sp, #368]
    stp q8, q9, [sp, #400]
    stp q10, q11, [sp, #432]
    stp q12, q13, [sp, #464]
    stp q14, q15, [sp, #496]
    stp q16, q17, [sp, #528]
    stp q18, q19, [sp, #560]
    stp q20, q21, [sp, #592]
    stp q22, q23, [sp, #624]
    stp q24, q25, [sp, #656]
    stp q26, q27, [sp, #688]
    stp q28, q29, [sp, #720]
    stp q30, q31, [sp, #752]
    mrs x16, fpcr
    mrs x17, fpsr
    str x16, [sp, #784]
    str x17, [sp, #792]
    mov x16, x0
    str xzr, [sp]
    mov x0, sp
    blr x16
    mov x17, sp
    ldp q0, q1, [x17, #272]
    ldp q2, q3, [x17, #304]
    ldp q4, q5, [x17, #336]
    ldp q6, q7, [x17, #368]
    ldp q8, q9, [x17, #400]
    ldp q10, q11, [x17, #432]
    ldp q12, q13, [x17, #464]
    ldp q14, q15, [x17, #496]
    ldp q16, q17, [x17, #528]
    ldp q18, q19, [x17, #560]
    ldp q20, q21, [x17, #592]
    ldp q22, q23, [x17, #624]
    ldp q24, q25, [x17, #656]
    ldp q26, q27, [x17, #688]
    ldp q28, q29, [x17, #720]
    ldp q30, q31, [x17, #752]
    ldr x14, [x17, #784]
    ldr x15, [x17, #792]
    msr fpcr, x14
    msr fpsr, x15
    ldr x16, [x17, #264]
    msr nzcv, x16
    ldr x16, [x17, #248]
    mov sp, x16
    ldr x16, [x17, #256]
    ldp x0, x1, [x17, #0]
    ldp x2, x3, [x17, #16]
    ldp x4, x5, [x17, #32]
    ldp x6, x7, [x17, #48]
    ldp x8, x9, [x17, #64]
    ldp x10, x11, [x17, #80]
    ldp x12, x13, [x17, #96]
    ldp x14, x15, [x17, #112]
    ldp x18, x19, [x17, #144]
    ldp x20, x21, [x17, #160]
    ldp x22, x23, [x17, #176]
    ldp x24, x25, [x17, #192]
    ldp x26, x27, [x17, #208]
    ldp x28, x29, [x17, #224]
    ldr x30, [x17, #240]
    ldr x17, [x17, #136]
    br x16
.size mochios_posix_signal_checkpoint, .-mochios_posix_signal_checkpoint
.section .note.GNU-stack,"",%progbits
