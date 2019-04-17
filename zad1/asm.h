#ifndef CROSSLD_ASM_H
#define CROSSLD_ASM_H

extern char exit_begin;
extern char exit_argument;
extern char exit_end;

__asm__ (
    "exit_begin:\n"
        "movq %rdi, %rax\n"
        "movabs $0, %rcx\n"
    "exit_argument:\n"
        "movq (%rcx), %rcx\n"
        "jmp *%rcx\n"
    "exit_end:\n"
);

extern char invoker_end;
extern char invoker_switcher;
extern char invoker_exit;
extern char invoker_struct;
extern char invoker_handler;
extern char invoker_begin;

__asm__ (
    "invoker_begin:\n"
        "movq %rdi, %r12\n"
        "movq %rsi, %r13\n"
        "movabs $0, %r14\n"
    "invoker_switcher:"
        "movabs $0, %r15\n"
    "invoker_exit:"
        "movabs $0, %rdi\n"
    "invoker_struct:\n"
        "movabs $0, %rax\n"
    "invoker_handler:\n"
        "jmp *%rax\n"
    "invoker_end:\n"
);

extern char trampoline_begin;
extern char trampoline_fun_ptr;
extern char trampoline_end;

__asm__ (
    "trampoline_begin:\n"
    ".code32\n"
        "subl $8, %esp\n"
        "movl $0x33, 4(%esp);\n"
        "movl $0, %eax;\n"
    "trampoline_fun_ptr:\n"
        "movl %eax, (%esp);\n"
        "lret;\n"
    ".code64\n"
    "trampoline_end:\n"
);

extern char starter_begin;
extern char starter_end;

__asm__ (

    "starter_begin:\n"
        ".code32\n"
        "pushl $0x2b\n"
        "popl %ds\n"
        "pushl $0x2b\n"
        "popl %es\n"
        "jmp *%ecx\n"
    ".code64\n"
    "starter_end:\n"
);

extern char switch_begin;
extern char switch_end;

__asm__ (

    "switch_begin:\n"
        ".code32\n"
        "pushl $0x2b\n"
        "popl %ds\n"
        "pushl $0x2b\n"
        "popl %es\n"
        "movl -0x8(%ebp), %ebx\n"
        "movl %ebp, %esp\n"
        "popl %ebp\n"
        "addl $4, %esp\n"
        "ret\n"
    ".code64\n"
    "switch_end:\n"
);

#endif //CROSSLD_ASM_H
