.intel_syntax noprefix
.text
.global invoke_guard
.type invoke_guard,@function
invoke_guard:
    push rbp
    mov rbp, rsp
    sub rsp, 0x2c8
    xor eax, eax
    jmp exact_guard
.size invoke_guard, .-invoke_guard
.section .exact_guard,"ax",@progbits
.global exact_guard
exact_guard:
    .byte 0x48,0x83,0x3d,0x6b,0x48,0x44,0x05,0x00
    .byte 0x0f,0x84,0x27,0x01,0x00,0x00
    mov eax, 1
    jmp exact_return
    .org 0x135, 0xcc
exact_return:
    .byte 0x48,0x81,0xc4,0xc8,0x02,0x00,0x00,0x5d,0xc3
.section .original_next,"aw",@nobits
.global original_next
original_next:
    .zero 8
.section .synthetic_next,"aw",@nobits
.global synthetic_next
synthetic_next:
    .zero 8
.section .note.GNU-stack,"",@progbits
