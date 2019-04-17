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
    void *args[to_invoke->nargs];

    void *switcher = 0;
    void *exit = 0;

    size_t stack_position = 8;
    size_t args_offset = 8;

    void* arg_val = 0;
    void* returned;

    __asm__ volatile (
        "movq %%r10, %0\n"
        "movq %%r11, %1\n"
    : "=m" (switcher), "=m" (exit)
    );

    for (int i = 0; i < to_invoke->nargs; i++) {
        enum type arg_type = to_invoke->args[i];
        arg_val = 0;
        switch (arg_type) {
            case TYPE_INT:
            case TYPE_LONG:
            case TYPE_UNSIGNED_INT:
            case TYPE_UNSIGNED_LONG:
            case TYPE_PTR:
                stack_position += 4;
                __asm__ volatile (
                    "movq %1, %%rax\n"
                    "lea (%%rbp, %%rax, 1), %%rax\n"
                    "movl (%%rax), %%eax\n"
                    "movl %%eax, %0\n"
                    : "=m" (arg_val)
                    : "g" (stack_position)
                );
                break;
            case TYPE_LONG_LONG:
            case TYPE_UNSIGNED_LONG_LONG:
                stack_position += 4;
                __asm__ volatile (
                    "movq %1, %%rax\n"
                    "lea (%%rbp, %%rax, 1), %%rax\n"
                    "movq (%%rax), %%rax\n"
                    "movq %%rax, %0\n"
                    : "=m" (arg_val)
                    : "g" (stack_position)
                );
                stack_position += 4;
                break;
        }

        args[i] = arg_val;
    }

//    printf("%s\n", to_invoke->name);

    for (int i = to_invoke->nargs; i > 5; i--) {
        long long val = (long long)args[i];
        __asm__ volatile (
            "pushq %0\n"
            :: "g" (val)
        );
    }

    for (int i = 0; i < to_invoke->nargs && i < 6; i++) {
        long long val = (long long)args[i];

        switch(i) {
            case 0:
                __asm__ volatile (
                    "movq %0, %%rdi"
                    :: "g" (val)
                );
                break;
            case 1:
                __asm__ volatile (
                    "movq %0, %%rsi"
                    :: "g" (val)
                );
                break;
            case 2:
                __asm__ volatile (
                    "movq %0, %%rdx"
                    :: "g" (val)
                );
                break;
            case 3:
                __asm__ volatile (
                    "movq %0, %%rcx"
                    :: "g" (val)
                );
                break;
            case 4:
                __asm__ volatile (
                    "movq %0, %%r8"
                    :: "g" (val)
                );
                break;
            case 5:
                __asm__ volatile (
                    "movq %0, %%r9"
                    :: "g" (val)
                );
                break;
        }
    }

    if (to_invoke->nargs >= 3) {
        long long val = (long long)args[2];
        __asm__ volatile (
            "movq %0, %%rdx"
            :: "g" (val)
        );
    }

    __asm__ volatile (
            "call *%1\n"
            "movq %%rax, %0\n"
        : "=m" (returned)
        : "g" (to_invoke->code)
    );

    unsigned long long returned_val = (unsigned long long)returned;

    switch(to_invoke->result) {
        case TYPE_VOID:
            __asm__ volatile (
                "movq %0, %%rcx\n"
                :: "g" (switcher)
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
                    :: "g" (exit)
                );
            } else {
                __asm__ volatile (
                    "movq %0, %%rax\n"
                    "movq %1, %%rcx;\n"
                    :: "g" (returned), "g" (switcher)
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
                :: "g" (switcher), "g" (returned)
            );
            break;
        default:
            break;
    }

    __asm__ volatile (
        "movq %r12, %rdi\n"
        "movq %r13, %rsi\n"
        "movq %r14, %rbx\n"
        "movl $0x23, 4(%rsp);\n"
        "movl %ecx, (%rsp);\n"
        "lret\n"
    );
}
