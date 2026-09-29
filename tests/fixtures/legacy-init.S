.intel_syntax noprefix
.text
.global legacy_entry, legacy_callback, legacy_callback_call, legacy_init_argument
.type legacy_entry,@function
legacy_entry:
    xor ebp, ebp
    mov r9, rdx
    pop rsi
    mov rdx, rsp
    and rsp, -16
    push rax
    push rsp
    xor r8d, r8d
legacy_init_argument:
    lea rcx, [rip + legacy_callback]
    lea rdi, [rip + main]
    call QWORD PTR [rip + __libc_start_main@GOTPCREL]
    hlt
.size legacy_entry,.-legacy_entry
.type legacy_callback,@function
legacy_callback:
    push rbp
    mov rbp, rsp
legacy_callback_call:
    call old_init
    pop rbp
    ret
.size legacy_callback,.-legacy_callback
.section .note.GNU-stack,"",@progbits
.ifdef TEST_PREINIT
.section .preinit_array,"aw",@preinit_array
.quad old_init
.endif
