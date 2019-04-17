#ifndef CROSSLD_PREPARATION_H
#define CROSSLD_PREPARATION_H

#include "common.h"

void* create_stack();

void* create_exit(long long return_address);

void* create_starter();

void* create_switcher();

void delete_stack(void *stack);

void* program_entry(const char *filename, const struct function *funcs, int nfuncs, struct State* state);

void* program_cleanup(int nfuncs, struct State* state);

#endif //CROSSLD_PREPARATION_H
