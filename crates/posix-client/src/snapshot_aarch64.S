// AAPCS64 continuation for an explicitly cloned address space.
.section .text.mochios_posix_capture_snapshot,"axG",%progbits,mochios_posix_capture_snapshot,comdat
.global mochios_posix_capture_snapshot
.type mochios_posix_capture_snapshot,%function
mochios_posix_capture_snapshot:
    sub sp, sp, #96
    stp d8, d9, [sp]
    stp d10, d11, [sp, #16]
    stp d12, d13, [sp, #32]
    stp d14, d15, [sp, #48]
    stp x29, x30, [sp, #64]
    stp x1, x2, [x0, #64]
    stp x3, x4, [x0, #80]
    stp x5, x6, [x0, #96]
    stp x7, x8, [x0, #112]
    stp x9, x10, [x0, #128]
    stp x11, x12, [x0, #144]
    stp x13, x14, [x0, #160]
    stp x15, x16, [x0, #176]
    stp x17, x18, [x0, #192]
    stp x19, x20, [x0, #208]
    stp x21, x22, [x0, #224]
    stp x23, x24, [x0, #240]
    stp x25, x26, [x0, #256]
    stp x27, x28, [x0, #272]
    stp x29, x30, [x0, #288]
    mov x16, sp
    str x16, [x0, #8]
    str x0, [x0, #16]
    str x1, [x0, #24]
    stp xzr, xzr, [x0, #32]
    stp xzr, xzr, [x0, #48]
    adr x16, .Lsnapshot_child
    str x16, [x0]
    blr x2
    b .Lsnapshot_resume
.Lsnapshot_child:
    mov x0, #0
.Lsnapshot_resume:
    ldp d8, d9, [sp]
    ldp d10, d11, [sp, #16]
    ldp d12, d13, [sp, #32]
    ldp d14, d15, [sp, #48]
    ldp x29, x30, [sp, #64]
    add sp, sp, #96
    ret
.size mochios_posix_capture_snapshot, .-mochios_posix_capture_snapshot
.section .note.GNU-stack,"",%progbits
