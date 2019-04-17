#include <stdio.h>

#include "crossld.h"
#include "common.h"
#include "preparation.h"

void prepare_state(const char *filename, const struct function *funcs, int nfuncs) {
    state.stack = create_stack();
    state.exit_fun = create_exit((long long)&(state.return_addr));
    state.exit_types[0] = TYPE_INT;
    state.exit_struct.nargs = 1;
    state.exit_struct.args = state.exit_types;
    state.exit_struct.result = TYPE_VOID;
    state.exit_struct.code = state.exit_fun;
    state.exit_struct.name = "exit";
    state.entry = program_entry(filename, funcs, nfuncs, state.exit_fun);
    state.starter = create_starter();
}

__attribute__ ((visibility("default")))
int crossld_start(const char *filename, const struct function *funcs, int nfuncs) {
    prepare_state(filename, funcs, nfuncs);
    if (get_status()) {
        return -1;
    }

    __asm__ volatile(
        "movq %%rbp, %2\n"
        "movq %3, %%rsp\n"
        "subq $8, %%rsp\n"
        "movl $0x23, 4(%%rsp)\n"
        "mov %4, %%rax\n"
        "movl %%eax, (%%rsp)\n"
        "mov %5, %%rcx\n"
        "lea 8(%%rip), %%rax\n" // instr after lret
        "mov %%rax, %0\n"
        "lret\n"
        "movq %%rax, %1\n"
        "movq %2, %%rbp\n"
        : "=m" (state.return_addr), "=m" (state.res), "=m" (state.rbp)
        : "g" (state.stack), "g" (state.starter), "g" (state.entry)
        : "cc", "memory", "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
        "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );

    program_cleanup(filename);
    return (long long)state.res;
}