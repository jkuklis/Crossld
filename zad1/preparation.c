#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

#include "preparation.h"
#include "asm.h"
#include "loader.h"


#define STACK_SIZE 3145728 // 3 * 1024 * 1024


void* create_switcher() {
    void* switcher;

    int code_len = &switch_end - &switch_begin;

    switcher = mmap(NULL, code_len, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);

    if (assert_msg(switcher != MAP_FAILED, "Failed to create switcher!")) {
        return 0;
    }

    memcpy(switcher, &switch_begin, code_len);

    mprotect(switcher, code_len, PROT_EXEC);

    return switcher;
}


void* create_stack() {
    void* stack;
    stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);

    if (assert_msg(stack != MAP_FAILED, "Failed to create stack!")) {
        return 0;
    }

    stack = (void*) (((uint64_t) stack) + STACK_SIZE - 4);

    return stack;
}


void delete_stack(void *stack) {
    stack = (void*) (((uint64_t) stack) - STACK_SIZE + 4);
    munmap(stack, STACK_SIZE);
}


void* create_exit(long long return_address) {
    size_t code_len = &exit_end - &exit_begin;
    size_t return_addr_offset = (&exit_argument - &exit_begin) - 8;

    void* exit_fun;

    exit_fun = mmap(NULL, code_len, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (assert_msg(exit_fun != MAP_FAILED, "Failed to create exit function!")) {
        return 0;
    }

    memcpy(exit_fun, &exit_begin, code_len);
    memcpy(exit_fun + return_addr_offset, &return_address, 8);
    mprotect(exit_fun, code_len, PROT_READ | PROT_EXEC);

    return exit_fun;
}


void* create_starter() {
    void* starter;

    int code_len = &starter_end - &starter_begin;

    starter = mmap(NULL, code_len, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);

    if (assert_msg(starter != MAP_FAILED, "Failed to create starter function!")) {
        return 0;
    }

    memcpy(starter, &starter_begin, code_len);
    mprotect(starter, code_len, PROT_EXEC);

    return starter;
}


void* program_entry(const char *filename, const struct function *funcs, int nfuncs, struct State* state) {
    static char buf[4 * 1024 * 1024];
    FILE* elf = fopen(filename, "rb");
    fread(buf, sizeof buf, 1, elf);

    void* entry = image_load(buf, funcs, nfuncs, state);

    return entry;
}

void* program_cleanup(int nfuncs, struct State* state) {
    size_t switcher_len = &switch_end - &switch_begin;
    size_t starter_len = &starter_end - &starter_begin;
    size_t exit_len = &exit_end - &exit_begin;

    munmap(state->switcher, switcher_len);
    munmap(state->starter, starter_len);
    munmap(state->exit_fun, exit_len);

    for (int i = 0; i < nfuncs; i++) {
        size_t invoker_len = &invoker_end - &invoker_begin;
        size_t trampoline_lne = &trampoline_end - &trampoline_begin;

        if (state->invokers[i]) {
            munmap(state->invokers[i], invoker_len);
        }

        if (state->trampolines[i]) {
            munmap(state->trampolines[i], trampoline_lne);
        }
    }

    state->return_addr = 0;
    state->stack = 0;
    state->exit_fun = 0;
    state->entry = 0;
    state->starter = 0;
    state->switcher = 0;
    state->trampolines = 0;
    state->invokers = 0;
    state->exit_struct.code = 0;
}