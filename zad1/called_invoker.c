#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "crossld.h"
#include "common.h"
#include "called_invoker.h"
#include "asm.h"


void called_invoker(const struct function *to_invoke) {
    // addresses of functions to switch back to 32-bit / exit the program
    void *switcher = 0;
    void *exit = 0;

    // stack position of the first argument of function
    size_t stack_position = 12;

    void* arg_val = 0;
    void* returned;

    __asm__ volatile (
        "movq %%r15, %0\n"
        "movq %%r11, %1\n"
    : "=m" (switcher), "=m" (exit)
    );

    size_t args_size = 6;
    if (to_invoke->nargs > 6) {
        args_size = to_invoke->nargs;
    }

    // arguments for the function to invoke
    void *args[args_size];

    for (int i = 0; i < to_invoke->nargs; i++) {
        enum type arg_type = to_invoke->args[i];
        arg_val = 0;
        switch (arg_type) {
            case TYPE_INT:
            case TYPE_LONG:
            case TYPE_UNSIGNED_INT:
            case TYPE_UNSIGNED_LONG:
            case TYPE_PTR:
                __asm__ volatile (
                    "movq %1, %%rax\n"
                    "lea (%%rbp, %%rax, 1), %%rax\n"
                    "movl (%%rax), %%eax\n"
                    "movl %%eax, %0\n"
                    : "=m" (arg_val)
                    : "m" (stack_position)
                );
                stack_position += 4;
                break;
            case TYPE_LONG_LONG:
            case TYPE_UNSIGNED_LONG_LONG:
                __asm__ volatile (
                    "movq %1, %%rax\n"
                    "lea (%%rbp, %%rax, 1), %%rax\n"
                    "movq (%%rax), %%rax\n"
                    "movq %%rax, %0\n"
                    : "=m" (arg_val)
                    : "m" (stack_position)
                );
                stack_position += 8;
                break;
        }

        args[i] = arg_val;
    }

    // push the arguments which do not fit in the registers to the stack
    for (int i = to_invoke->nargs; i > 5; i--) {
        long long val = (long long)args[i];
        __asm__ volatile (
            "pushq %0\n"
            :: "m" (val)
        );
    }

    register void* rdi __asm__("%rdi") = args[0];
    register void* rsi __asm__("%rsi") = args[1];
    register void* rdx __asm__("%rdx") = args[2];
    register void* rcx __asm__("%rcx") = args[3];
    register void* r8 __asm__("%r8") = args[4];
    register void* r9 __asm__("%r9") = args[5];

    __asm__ volatile (
            "call *%1\n"
            "movq %%rax, %0\n"
        : "=m" (returned)
        : "g" (to_invoke->code), "g" (rdi), "g" (rsi), "g" (rdx), "g" (rcx), "g" (r8), "g" (r9)
    );

    unsigned long long returned_val = (unsigned long long)returned;

    switch(to_invoke->result) {
        case TYPE_VOID:
            __asm__ volatile (
                "movq %0, %%rcx\n"
                :: "m" (switcher)
            );
            break;
        case TYPE_INT:
        case TYPE_LONG:
        case TYPE_UNSIGNED_INT:
        case TYPE_UNSIGNED_LONG:
        case TYPE_PTR:
            if (returned_val > UINT32_MAX) {
                __asm__ volatile (
                    "movq $-1, %%rdi\n"
                    "jmp *%0"
                    :: "m" (exit)
                );
            } else {
                __asm__ volatile (
                    "movq %0, %%rax\n"
                    "movq %1, %%rcx;\n"
                    :: "m" (returned), "m" (switcher)
                );
            }
            break;

        case TYPE_LONG_LONG:
        case TYPE_UNSIGNED_LONG_LONG:
            __asm__ volatile (
                "movq %0, %%rcx\n"
                "movq %1, %%rdx\n"
                "movl %%edx, %%eax\n"
                "sar $32, %%rdx\n"
                :: "m" (switcher), "m" (returned)
            );
            break;
        default:
            break;
    }

    // restore registers (%ebp, %esp later), return to switcher and come back to 32-bit program
    __asm__ volatile (
        "movq %r12, %rdi\n"
        "movq %r13, %rsi\n"
        "movq %r14, %rbx\n"
        "movl $0x23, 4(%rsp);\n"
        "movl %ecx, (%rsp);\n"
        "lret\n"
    );
}
