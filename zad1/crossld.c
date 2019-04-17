#include <stdio.h>

#include "crossld.h"
#include "common.h"
#include "preparation.h"
#include "loader.h"

void *res;
void *rbp;
void *rsp;


void prepare_state(struct State* state, const struct function *funcs, int nfuncs, void **trampolines, void **invokers) {
    state->stack = create_stack();
    state->starter = create_starter();
    state->switcher = create_switcher();
    state->exit_types[0] = TYPE_INT;
    state->exit_struct.nargs = 1;
    state->exit_struct.args = state->exit_types;
    state->exit_struct.result = TYPE_VOID;
    state->exit_struct.code = create_exit((long long)&(state->return_addr));
    state->exit_struct.name = "exit";
    state->trampolines = trampolines;
    state->invokers = invokers;
}

// exporting only crossld_start
__attribute__ ((visibility("default")))
int crossld_start(const char *filename, const struct function *funcs, int nfuncs) {
    struct State state;

    void* trampolines[nfuncs + 1];
    void* invokers[nfuncs + 1];

    prepare_state(&state, funcs, nfuncs, trampolines, invokers);

    // open the elf file and read it into a buffer
    FILE* elf = fopen(filename, "rb");
    assert_msg(elf != 0, "Failed to open file!");

    fseek(elf, 0, SEEK_END);
    size_t elf_size = ftell(elf);
    rewind(elf);

    char buf[elf_size];
    fread(buf, 1, elf_size, elf);

    // load the program into memory, create trampolines and replace jmp_slots addresses
    state.entry = image_load(buf, funcs, nfuncs, &state);

    // if anywhere along the way so far there was an error, return -1
    if (get_status()) {
        return -1;
    }

    __asm__ volatile(
        "movq %%rsp, %3\n"      // save registers
        "movq %%rbp, %2\n"
        "movq %4, %%rsp\n"      // stack for the 32-bit program
        "subq $8, %%rsp\n"      // prepare for 32-bit long return
        "movl $0x23, 4(%%rsp)\n"
        "mov %5, %%rax\n"
        "movl %%eax, (%%rsp)\n"
        "mov %6, %%rcx\n"
        "lea 8(%%rip), %%rax\n" // instr after lret, needed for exit function
        "mov %%rax, %0\n"
        "lret\n"
        "movq %%rax, %1\n"      // restore key registers, the rest will be restored before returning
        "movq %2, %%rbp\n"
        "movq %3, %%rsp\n"
        : "=m" (state.return_addr), "=m" (res), "=m" (rbp), "=m" (rsp)
        : "g" (state.stack), "g" (state.starter), "g" (state.entry)
        : "cc", "memory", "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
        "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );

    unload_program(buf);
    program_cleanup(nfuncs, &state);
    fclose(elf);

    reset_status();
    return (long long)res;
}