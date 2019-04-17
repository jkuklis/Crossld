#include <stdio.h>

#include "crossld.h"
#include "common.h"
#include "preparation.h"
#include "loader.h"

void prepare_state(struct State* state, const struct function *funcs, int nfuncs, void **trampolines, void **invokers) {
    state->rbp = 0;
    state->res = 0;
    state->stack = create_stack();
    state->starter = create_starter();
    state->switcher = create_switcher();
    state->exit_fun = create_exit((long long)&(state->return_addr));
    state->exit_types[0] = TYPE_INT;
    state->exit_struct.nargs = 1;
    state->exit_struct.args = state->exit_types;
    state->exit_struct.result = TYPE_VOID;
    state->exit_struct.code = state->exit_fun;
    state->exit_struct.name = "exit";
    state->trampolines = trampolines;
    state->invokers = invokers;
}

__attribute__ ((visibility("default")))
int crossld_start(const char *filename, const struct function *funcs, int nfuncs) {
    struct State state;

    void* trampolines[nfuncs + 1];
    void* invokers[nfuncs + 1];

    prepare_state(&state, funcs, nfuncs, trampolines, invokers);

    static char buf[4 * 1024 * 1024];
    FILE* elf = fopen(filename, "rb");
    fread(buf, sizeof buf, 1, elf);

    state.entry = image_load(buf, funcs, nfuncs, &state);

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

    unload_program(buf);
    program_cleanup(nfuncs, &state);

    reset_status();
    return (long long)state.res;
}