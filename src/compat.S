    .text

    .globl compat_start
    .globl compat_end
    .globl call32_enter
    .globl call64_enter
    .globl call64_dispatch
compat_start:

    .code64
    // uint32_t call32(uint32_t rdi/fn, uint32_t rsi/stack_top, const uint32_t* rdx/args, uint32_t rcx/nargs)
    // Enters in SysV x86-64 (must preserve rbx, rbp, rsp, r12-r15)
    // stack_top == 0 means we're already on the 32-bit stack
call32_enter:
    // Remember preserved (non-sp) registers
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    // Save 64-bit sp on 32-bit stack, move to 32-bit stack, and save 32-bit sp in ebx
    mov %rsp, %rax
    test %esi, %esi
    jz .Lcall32_keep_stack
    mov %esi, %esp
.Lcall32_keep_stack:
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
    // Far jump to call32_in32 in 32-bit mode
    pushq $0x23
    lea call32_restore(%rip), %rsi
    lea call32_in32(%rip), %rax
    push %rax
    lretq

    .code32
    // Now in 32-bit mode, with args setup for i386 windows abi
call32_in32:
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
call32_restore:
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

    .code32
    // Enters in i386 cdecl (must preserve ebx, esi, edi, ebp, esp)
    // SysV callee preserves (rbx, rsp, rbp)
    // void elfinator_call64(uint32_t idx, const uint64_t* args, uint64_t* ret)
    //   args on stack
call64_enter:
    push %ebp
    mov %esp, %ebp // save sp since we do a 16-byte align later

    // Save callee saved regs
    push %ebx
    push %esi
    push %edi

    // Get call64_in64 address (no rip-relative)
    call .Lcall64_measure_pos
.Lcall64_measure_pos:
    pop %eax
    lea (call64_in64 - .Lcall64_measure_pos)(%eax), %ecx

    // Jump to 64-bit
    push $0x33
    push %ecx
    lret

    .code64
    // In 64-bit mode on 32-bit stack
call64_in64:
    mov %esp, %esp // zero-extend
    mov %ebp, %ebp

    // Move cdecl args to sysv (edi, esi, edx)
    mov 8(%rbp), %edi
    mov 12(%rbp), %esi
    mov 16(%rbp), %edx

    // Call fn
    and $-16, %rsp // 16-byte align
    call *call64_dispatch(%rip)

    // Return
    lea call64_restore(%rip), %rax
    pushq $0x23
    push %rax
    lretq

    .code32
    // Back in 32-bit
call64_restore:
    lea -12(%ebp), %esp
    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret

    .balign 8
call64_dispatch:
    .quad 0
compat_end:

    .section .note.GNU-stack, "", @progbits
