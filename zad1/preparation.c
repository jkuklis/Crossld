#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

#include "preparation.h"
#include "asm.h"
#include "loader.h"


#define STACK_SIZE 3145728 // 3 * 1024 * 1024


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

    if ((starter = mmap(NULL, code_len, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0)) == MAP_FAILED) {
        printf("bad switch mmap\n");
    }

    memcpy(starter, &starter_begin, code_len);
    mprotect(starter, code_len, PROT_EXEC);

    return starter;
}


void* program_entry(const char *filename, const struct function *funcs, int nfuncs, void* exit_fun) {
    // TODO
    static char buf[4 * 1024 * 1024];
    FILE* elf = fopen(filename, "rb");
    fread(buf, sizeof buf, 1, elf);

    void* entry = image_load(buf, funcs, nfuncs, exit_fun);

    return entry;
}

void* program_cleanup(const char *filename) {
    static char buf[4 * 1024 * 1024];
    FILE* elf = fopen(filename, "rb");
    fread(buf, sizeof buf, 1, elf);

    unload_program(buf);
}