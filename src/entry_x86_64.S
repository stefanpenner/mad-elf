/* Process entry for the freestanding PT_INTERP shim.
 * The kernel enters with rsp pointing at argc. Align before the C call
 * so compiled code can use aligned SSE moves.
 * .text has to come first: a .section directive above _start would assemble
 * the entry point into the note and the kernel would jump to address 0.
 */
.section .text
.global _start
_start:
    mov %rsp, %rdi
    and $-16, %rsp
    call madelf_main
    mov %rax, %rdi
    mov $60, %rax
    xor %rsi, %rsi
    syscall

.section .note.GNU-stack,"",@progbits
