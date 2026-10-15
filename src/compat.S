    .text

// uint32_t call32(uint32_t edi/fn, uint32_t esi/stack_top, const uint32_t* rdx/args, uint32_t ecx/nargs)
    // Position independent, copied below 4GB by compat_init (far jumps truncate to 32 bits)
    .globl call32_start
    .globl call32_end
    .code64
    // Enters in SysV x86-64 (must preserve rbx, rbp, rsp, r12-r15)
call32_start:
    // Remember preserved (non-sp) registers
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    // Save 64-bit sp on 32-bit stack, move to 32-bit stack, and save 32-bit sp in ebx
    mov %rsp, %rax
    mov %esi, %esp
    push %rax
    mov %esp, %ebx // `fn` could be cdecl (callee doesn't clean stack), so save esp (ebx is preserved by i386 windows)

    // Reserve nargs * 4 bytes on 32-bit stack and align sp
    mov %ecx, %ecx // zero-extend
    lea (, %rcx, 4), %eax
    sub %rax, %rsp
    and $-16, %rsp // 16-byte align for call

    test %ecx, %ecx
    jz .Lcall32_args_done
.Lcall32_copy_arg:
    // Loop to copy arguments to stack (for i386 windows abi)
    mov -4(%rdx, %rcx, 4), %eax // eax = args[rcx - 1]
    mov %eax, -4(%rsp, %rcx, 4) // store in stack slot rcx - 1
    dec %ecx
    jnz .Lcall32_copy_arg
.Lcall32_args_done:
    // Far jump to enter_call32 in 32-bit mode
    pushq $0x23
    lea leave_call32(%rip), %rsi
    lea enter_call32(%rip), %rax
    push %rax
    lretq

    .code32
    // Now in 32-bit mode, with args setup for i386 windows abi
enter_call32:
    // Load DS and ES and call fn (in edi)
    mov $0x2b, %eax
    mov %eax, %ds
    mov %eax, %es
    call *%edi

    // Return to 64-bit mode
    push $0x33
    push %esi
    lret

    .code64
    // Now in 64-bit with return in EAX
leave_call32:
    mov %ebx, %esp // cdecl callees leave their args behind, esp can't be trusted
    pop %rsp // restore 64-bit stack
    pop %r15 // restore callee-saved registers to get back to SysV abi
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    mov %eax, %eax // top half of rax is undefined, zero-extend
    ret
call32_end:

    .section .note.GNU-stack, "", @progbits
